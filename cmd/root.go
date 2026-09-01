package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/calypso-scanner/calypso/internal/config"
	"github.com/calypso-scanner/calypso/internal/store"
	"github.com/calypso-scanner/calypso/internal/ui"
	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "calypso",
	Short: "Defend before you open.",
	Long:  `Calypso — professional-grade command-line malware scanner with real-time protection.`,
	RunE:  runInteractive,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ~/.calypso/config.yaml)")
}

func initConfig() {
	if cfgFile != "" {
		os.Setenv("CALYPSO_CONFIG", cfgFile)
	}
}

func runInteractive(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return cmd.Help()
	}

	model := ui.NewMainMenuModel()
	p := tea.NewProgram(model, tea.WithAltScreen())

	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	result, ok := finalModel.(ui.MainMenuModel)
	if !ok || !result.Submitted() {
		return nil
	}

	action := result.GetAction()
	path := result.GetPath()

	switch action {
	case "Scan":
		return runScanFromMenu(path)
	case "Watch":
		return runWatchFromMenu(path)
	case "History":
		return runHistoryFromMenu()
	case "Quarantine":
		return runQuarantineFromMenu()
	case "Update":
		return runUpdateFromMenu()
	case "Doctor":
		return runDoctorFromMenu()
	case "Config":
		return runConfigFromMenu()
	}

	return nil
}

func runScanFromMenu(path string) error {
	cfg := getConfig()
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	scanFiles, err := collectScanFiles(absPath, false, cfg.ExcludedPaths)
	if err != nil {
		return fmt.Errorf("error: %v", err)
	}

	if len(scanFiles) == 0 {
		fmt.Println("No files found to scan.")
		return nil
	}

	return runScanTUI(scanFiles, cfg)
}

func runWatchFromMenu(path string) error {
	cfg := getConfig()
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	return runWatchTUI(absPath, cfg)
}

func runHistoryFromMenu() error {
	cfg := getConfig()
	sdb, err := storeOpen(cfg)
	if err != nil {
		return err
	}
	defer sdb.Close()

	records, err := sdb.GetHistory(50)
	if err != nil {
		return err
	}

	if len(records) == 0 {
		fmt.Println("No scan history.")
		return nil
	}

	fmt.Printf("%-4s %-12s %-8s %s\n", "ID", "VERDICT", "SCORE", "FILE")
	fmt.Println("---", "------------", "--------", "------------------------------------------")
	for _, r := range records {
		fmt.Printf("%-4d %-12s %-8.0f %s\n", r.ID, r.Verdict, r.Score, r.FilePath)
	}
	return nil
}

func runQuarantineFromMenu() error {
	cfg := getConfig()
	sdb, err := storeOpen(cfg)
	if err != nil {
		return err
	}
	defer sdb.Close()

	records, err := sdb.ListQuarantine()
	if err != nil {
		return err
	}

	if len(records) == 0 {
		fmt.Println("No quarantined files.")
		return nil
	}

	fmt.Printf("%-4s %-30s %-12s %-8s %s\n", "ID", "FILE", "VERDICT", "SCORE", "ORIGINAL PATH")
	fmt.Println("---", "-------------------------------", "------------", "--------", "---------------------")
	for _, r := range records {
		fmt.Printf("%-4d %-30s %-12s %-8.0f %s\n", r.ID, r.FileName, r.Verdict, r.Score, r.OriginalPath)
	}
	return nil
}

func runUpdateFromMenu() error {
	cfg := getConfig()
	return runUpdate(cfg)
}

func runDoctorFromMenu() error {
	return runDoctor()
}

func runConfigFromMenu() error {
	cfg := getConfig()
	return runConfig(cfg)
}

func storeOpen(cfg *config.Config) (*store.Store, error) {
	return store.New(cfg.DBPath)
}

func getConfig() *config.Config {
	cfg, err := config.Load()
	if err != nil {
		cfg = &config.Config{
			Engines: config.Engines{
				Hash:      true,
				FileType:  true,
				ClamAV:    true,
				Yara:      true,
				Heuristic: true,
				Cloud:     false,
			},
			DBPath:         config.DefaultDBPath(),
			QuarantinePath: config.DefaultQuarantinePath(),
			RulesPath:      config.DefaultRulesPath(),
			ExcludedPaths:  []string{},
			Theme:          "default",
		}
	}
	return cfg
}

func collectScanFiles(absPath string, recursive bool, excluded []string) ([]string, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("cannot access path: %v", err)
	}

	if !info.IsDir() {
		return []string{absPath}, nil
	}

	return collectFiles(absPath, recursive, excluded)
}
