package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/calypso-scanner/calypso/internal/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "View or edit Calypso configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := getConfig()
		return runConfig(cfg)
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}

func runConfig(cfg *config.Config) error {
	cfgPath := filepath.Join(config.DefaultConfigPath(), "config.yaml")

	fmt.Println("Calypso Configuration")
	fmt.Println("====================")
	fmt.Println()
	fmt.Printf("  Config file:     %s\n", cfgPath)
	fmt.Printf("  Database:        %s\n", cfg.DBPath)
	fmt.Printf("  Quarantine:      %s\n", cfg.QuarantinePath)
	fmt.Printf("  Rules path:      %s\n", cfg.RulesPath)
	fmt.Printf("  Theme:           %s\n", cfg.Theme)
	fmt.Printf("  VT API key:      %s\n", maskKey(cfg.VirusTotalAPIKey))
	fmt.Printf("  Deep scan:       %v\n", cfg.DeepScanConfirmed)
	fmt.Println()
	fmt.Println("  Engines:")
	fmt.Printf("    Hash:          %v\n", cfg.Engines.Hash)
	fmt.Printf("    File Type:     %v\n", cfg.Engines.FileType)
	fmt.Printf("    ClamAV:        %v\n", cfg.Engines.ClamAV)
	fmt.Printf("    YARA:          %v\n", cfg.Engines.Yara)
	fmt.Printf("    Heuristic:     %v\n", cfg.Engines.Heuristic)
	fmt.Printf("    Cloud:         %v\n", cfg.Engines.Cloud)
	fmt.Println()
	fmt.Printf("  To edit, open: %s\n", cfgPath)

	if !isInteractive() {
		return nil
	}

	fmt.Println()
	fmt.Print("  Open in editor? [y/N] ")
	var answer string
	fmt.Scanln(&answer)

	if answer == "y" || answer == "Y" {
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "notepad"
		}
		editorCmd := exec.Command(editor, cfgPath)
		editorCmd.Stdin = os.Stdin
		editorCmd.Stdout = os.Stdout
		editorCmd.Stderr = os.Stderr
		return editorCmd.Run()
	}

	return nil
}

func maskKey(key string) string {
	if key == "" {
		return "(not set)"
	}
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "****" + key[len(key)-4:]
}
