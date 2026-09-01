package cmd

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/calypso-scanner/calypso/internal/config"
	"github.com/calypso-scanner/calypso/internal/engine"
	"github.com/calypso-scanner/calypso/internal/orchestrator"
	"github.com/calypso-scanner/calypso/internal/store"
	"github.com/calypso-scanner/calypso/internal/ui"
	"github.com/spf13/cobra"
)

var (
	scanRecursive bool
	scanDeep      bool
	scanEngines   string
	scanJSON      bool
	scanQuarantine bool
	scanNoTUI     bool
)

var scanCmd = &cobra.Command{
	Use:   "scan <path>",
	Short: "Scan a file or directory for threats",
	Long:  `Run Calypso's layered detection pipeline against the specified file or directory.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().BoolVarP(&scanRecursive, "recursive", "r", false, "Scan directories recursively")
	scanCmd.Flags().BoolVar(&scanDeep, "deep", false, "Enable full-file cloud analysis (requires VirusTotal API key)")
	scanCmd.Flags().StringVar(&scanEngines, "engines", "", "Comma-separated list of engines to use")
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "Output results as JSON")
	scanCmd.Flags().BoolVar(&scanQuarantine, "quarantine", false, "Auto-quarantine detected threats")
	scanCmd.Flags().BoolVar(&scanNoTUI, "no-tui", false, "Disable interactive TUI (for scripting)")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	scanPath := args[0]
	cfg := getConfig()

	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("cannot access path: %w", err)
	}

	var files []string
	if !info.IsDir() {
		files = []string{absPath}
	} else {
		files, err = collectFiles(absPath, scanRecursive, cfg.ExcludedPaths)
		if err != nil {
			return fmt.Errorf("collecting files: %w", err)
		}
	}

	if len(files) == 0 {
		fmt.Println("No files found to scan.")
		return nil
	}

	if scanJSON || scanNoTUI {
		return runScanPlain(files, cfg)
	}

	if isInteractive() {
		return runScanTUI(files, cfg)
	}

	return runScanPlain(files, cfg)
}

func runScanTUI(files []string, cfg *config.Config) error {
	sdb, err := store.New(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer sdb.Close()

	engines := buildEngines(cfg, scanEngines, scanDeep, sdb)

	engineNames := make([]string, len(engines))
	for i, e := range engines {
		engineNames[i] = e.Name()
	}

	orc := orchestrator.New()

	for _, filePath := range files {
		model := ui.NewScanModel(filePath, engineNames)

		p := tea.NewProgram(model, tea.WithAltScreen())

		go func(fp string) {
			ctx := context.Background()
			result := orc.Scan(ctx, orchestrator.ScanRequest{
				FilePath: fp,
				Engines:  engines,
			}, func(status orchestrator.EngineStatus) {
				dur := ""
				if status.Result != nil {
					dur = status.Result.Duration.Round(time.Millisecond).String()
				}
				p.Send(ui.EngineUpdateMsg{
					Name:     status.Name,
					Status:   status.Status,
					Duration: dur,
				})
			})

			var findings []ui.FindingDisplay
			for _, f := range result.Findings {
				findings = append(findings, ui.FindingDisplay{
					Engine:      f.Engine,
					Rule:        f.Rule,
					Description: f.Description,
					Severity:    f.Severity,
				})
			}

			p.Send(ui.ScanCompleteMsg{
				Verdict:  result.Verdict,
				Score:    result.Score,
				Findings: findings,
			})

			persistScan(sdb, fp, result, engineNamesToString(engines))

			if scanQuarantine && (result.Verdict == "malicious" || result.Verdict == "suspicious") {
				quarantineFile(cfg, fp, result, sdb)
			}
		}(filePath)

		if _, err := p.Run(); err != nil {
			return fmt.Errorf("TUI error: %w", err)
		}
	}

	return nil
}

func runScanPlain(files []string, cfg *config.Config) error {
	sdb, err := store.New(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer sdb.Close()

	engines := buildEngines(cfg, scanEngines, scanDeep, sdb)

	orc := orchestrator.New()

	for _, filePath := range files {
		if scanJSON {
			fmt.Fprintf(os.Stderr, "Scanning: %s\n", filePath)
		} else {
			fmt.Printf("Scanning: %s\n", filePath)
		}

		ctx := context.Background()
		result := orc.Scan(ctx, orchestrator.ScanRequest{
			FilePath: filePath,
			Engines:  engines,
		}, nil)

		if scanJSON {
			output := map[string]interface{}{
				"file":    filePath,
				"verdict": result.Verdict,
				"score":   result.Score,
				"findings": func() []map[string]interface{} {
					var out []map[string]interface{}
					for _, f := range result.Findings {
						out = append(out, map[string]interface{}{
							"engine":      f.Engine,
							"rule":        f.Rule,
							"description": f.Description,
							"severity":    f.Severity,
						})
					}
					return out
				}(),
			}
			jsonBytes, _ := json.MarshalIndent(output, "", "  ")
			fmt.Println(string(jsonBytes))
		} else {
			printPlainResult(result)
		}

		persistScan(sdb, filePath, result, engineNamesToString(engines))

		if scanQuarantine && (result.Verdict == "malicious" || result.Verdict == "suspicious") {
			quarantineFile(cfg, filePath, result, sdb)
		}
	}

	return nil
}

func printPlainResult(result orchestrator.ScanResult) {
	var verdictColor string
	switch result.Verdict {
	case "clean":
		verdictColor = "\033[32m"
	case "suspicious":
		verdictColor = "\033[33m"
	case "malicious":
		verdictColor = "\033[31m"
	}
	reset := "\033[0m"

	fmt.Printf("  Verdict: %s%s%s  (Score: %.0f/100)\n", verdictColor, strings.ToUpper(result.Verdict), reset, result.Score)

	if len(result.Findings) > 0 {
		fmt.Println("  Findings:")
		for _, f := range result.Findings {
			fmt.Printf("    [%s] %s — %s (severity: %.0f%%)\n", f.Rule, f.Engine, f.Description, f.Severity*100)
		}
	}
	fmt.Println()
}

func buildEngines(cfg *config.Config, engineFilter string, deep bool, sdb *store.Store) []engine.ScanEngine {
	enabled := map[string]bool{
		"hash":      cfg.Engines.Hash,
		"file_type": cfg.Engines.FileType,
		"clamav":    cfg.Engines.ClamAV,
		"yara":      cfg.Engines.Yara,
		"heuristic": cfg.Engines.Heuristic,
		"cloud":     cfg.Engines.Cloud,
	}

	if engineFilter != "" {
		for k := range enabled {
			enabled[k] = false
		}
		for _, e := range strings.Split(engineFilter, ",") {
			enabled[strings.TrimSpace(e)] = true
		}
	}

	var engines []engine.ScanEngine

	if enabled["hash"] {
		engines = append(engines, engine.NewHashEngine(sdb))
	}
	if enabled["file_type"] {
		engines = append(engines, engine.NewFileTypeEngine())
	}
	if enabled["clamav"] {
		engines = append(engines, engine.NewClamAVEngine())
	}
	if enabled["yara"] {
		engines = append(engines, engine.NewYaraEngine(cfg.RulesPath))
	}
	if enabled["heuristic"] {
		engines = append(engines, engine.NewHeuristicEngine())
	}
	if deep && enabled["cloud"] && cfg.VirusTotalAPIKey != "" {
		engines = append(engines, engine.NewCloudEngine(cfg.VirusTotalAPIKey))
	}

	if len(engines) == 0 {
		engines = append(engines,
			engine.NewHashEngine(sdb),
			engine.NewFileTypeEngine(),
			engine.NewHeuristicEngine(),
		)
	}

	return engines
}

func collectFiles(root string, recursive bool, excluded []string) ([]string, error) {
	var files []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		for _, excl := range excluded {
			if strings.HasPrefix(path, excl) {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		if !info.IsDir() && info.Mode().IsRegular() {
			files = append(files, path)
		}

		if !recursive && info.IsDir() && path != root {
			return filepath.SkipDir
		}

		return nil
	})

	return files, err
}

func engineNamesToString(engines []engine.ScanEngine) string {
	names := make([]string, len(engines))
	for i, e := range engines {
		names[i] = e.Name()
	}
	return strings.Join(names, ",")
}

func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// persistScan logs the result to the store and seeds the blocklist whenever any
// engine produced a malicious verdict, so future lookups match by hash.
func persistScan(sdb *store.Store, path string, result orchestrator.ScanResult, engineNames string) {
	sha256Hex, md5Hex, _ := fileHashes(path)

	_ = sdb.LogScan(store.ScanRecord{
		FilePath: path,
		SHA256:   sha256Hex,
		MD5:      md5Hex,
		Verdict:  result.Verdict,
		Score:    result.Score,
		Engines:  engineNames,
	})

	var sources []string
	for _, es := range result.Engines {
		if es.Result != nil && es.Result.Status == engine.StatusMalicious {
			sources = append(sources, es.Name)
		}
	}

	if len(sources) > 0 && sha256Hex != "" {
		_ = sdb.AddToBlocklist(sha256Hex, md5Hex, "malicious", strings.Join(sources, ","))
	}
}

func fileHashes(path string) (sha256Hex, md5Hex string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	sha256Hasher := sha256.New()
	md5Hasher := md5.New()
	if _, err := io.Copy(io.MultiWriter(sha256Hasher, md5Hasher), f); err != nil {
		return "", "", err
	}

	return hex.EncodeToString(sha256Hasher.Sum(nil)), hex.EncodeToString(md5Hasher.Sum(nil)), nil
}

func quarantineFile(cfg *config.Config, filePath string, result orchestrator.ScanResult, sdb *store.Store) {
	qDir := cfg.QuarantinePath
	if err := os.MkdirAll(qDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: cannot create quarantine directory: %v\n", err)
		return
	}

	uuid := fmt.Sprintf("%d", time.Now().UnixNano())
	destDir := filepath.Join(qDir, uuid)
	if err := os.MkdirAll(destDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: cannot create quarantine subdirectory: %v\n", err)
		return
	}

	destPath := filepath.Join(destDir, filepath.Base(filePath))

	// Move the file into quarantine. Prefer a rename (same filesystem) so the
	// file stays recoverable end-to-end; fall back to copy+delete only if the
	// rename fails (e.g. quarantine lives on a different filesystem). Either
	// way the original path is no longer occupied, so no stuck/ghost copy.
	if err := os.Rename(filePath, destPath); err != nil {
		if copyErr := copyFile(filePath, destPath); copyErr != nil {
			fmt.Fprintf(os.Stderr, "  Warning: quarantine failed: %v\n", err)
			return
		}
		if removeErr := os.Remove(filePath); removeErr != nil {
			fmt.Fprintf(os.Stderr, "  Warning: quarantine copy succeeded but could not remove original: %v\n", removeErr)
		}
	}

	_ = sdb.AddQuarantine(store.QuarantineRecord{
		OriginalPath:   filePath,
		QuarantinePath: destPath,
		FileName:       filepath.Base(filePath),
		Verdict:        result.Verdict,
		Score:          result.Score,
	})

	fmt.Printf("  Quarantined: %s → %s\n", filePath, destPath)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	buf := make([]byte, 64*1024)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			break
		}
	}
	return nil
}
