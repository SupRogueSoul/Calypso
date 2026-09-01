package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/fsnotify/fsnotify"

	"github.com/calypso-scanner/calypso/internal/config"
	"github.com/calypso-scanner/calypso/internal/orchestrator"
	"github.com/calypso-scanner/calypso/internal/store"
	"github.com/calypso-scanner/calypso/internal/ui"
	"github.com/spf13/cobra"
)

var watchNoTUI bool

var watchCmd = &cobra.Command{
	Use:   "watch <dir>",
	Short: "Watch a directory for new files and scan automatically",
	Long:  `Monitor a directory in real-time using filesystem events, scanning new files as they appear.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runWatch,
}

func init() {
	watchCmd.Flags().BoolVar(&watchNoTUI, "no-tui", false, "Disable interactive TUI")
	rootCmd.AddCommand(watchCmd)
}

func runWatch(cmd *cobra.Command, args []string) error {
	dir := args[0]
	cfg := getConfig()

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	if _, err := os.Stat(absDir); err != nil {
		return fmt.Errorf("cannot access directory: %w", err)
	}

	if watchNoTUI || !isInteractive() {
		return runWatchPlain(absDir, cfg)
	}

	return runWatchTUI(absDir, cfg)
}

func runWatchTUI(dir string, cfg *config.Config) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(dir); err != nil {
		return fmt.Errorf("watching directory: %w", err)
	}

	sdb, err := store.New(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer sdb.Close()

	engines := buildEngines(cfg, "", false, sdb)
	orc := orchestrator.New()

	p := tea.NewProgram(ui.NewWatchModel(dir, 80, 24), tea.WithAltScreen())

	go func() {
		seen := make(map[string]bool)

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Create == 0 {
					continue
				}

				info, err := os.Stat(event.Name)
				if err != nil || info.IsDir() {
					continue
				}

				if seen[event.Name] {
					continue
				}
				seen[event.Name] = true

				time.Sleep(100 * time.Millisecond)

				ctx := context.Background()
				result := orc.Scan(ctx, orchestrator.ScanRequest{
					FilePath: event.Name,
					Engines:  engines,
				}, nil)

				entry := ui.WatchEntry{
					Timestamp: time.Now(),
					FilePath:  event.Name,
					Verdict:   result.Verdict,
					Score:     result.Score,
				}

				p.Send(ui.WatchScanResultMsg{Entry: entry})

				_ = sdb.LogScan(store.ScanRecord{
					FilePath: event.Name,
					Verdict:  result.Verdict,
					Score:    result.Score,
					Engines:  engineNamesToString(engines),
				})

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				p.Send(ui.WatchEventMsg{Message: fmt.Sprintf("Watch error: %v", err)})
			}
		}
	}()

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	return nil
}

func runWatchPlain(dir string, cfg *config.Config) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(dir); err != nil {
		return fmt.Errorf("watching directory: %w", err)
	}

	sdb, err := store.New(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer sdb.Close()

	engines := buildEngines(cfg, "", false, sdb)
	orc := orchestrator.New()

	fmt.Printf("Watching %s for new files... (Ctrl+C to stop)\n", dir)

	seen := make(map[string]bool)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if event.Op&fsnotify.Create == 0 {
				continue
			}

			info, err := os.Stat(event.Name)
			if err != nil || info.IsDir() {
				continue
			}

			if seen[event.Name] {
				continue
			}
			seen[event.Name] = true

			time.Sleep(100 * time.Millisecond)

			fmt.Printf("\nNew file: %s\n", event.Name)

			ctx := context.Background()
			result := orc.Scan(ctx, orchestrator.ScanRequest{
				FilePath: event.Name,
				Engines:  engines,
			}, nil)

			printPlainResult(result)

			_ = sdb.LogScan(store.ScanRecord{
				FilePath: event.Name,
				Verdict:  result.Verdict,
				Score:    result.Score,
				Engines:  engineNamesToString(engines),
			})

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			fmt.Fprintf(os.Stderr, "Watch error: %v\n", err)
		}
	}
}
