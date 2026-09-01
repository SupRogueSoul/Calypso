package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/calypso-scanner/calypso/internal/store"
	"github.com/spf13/cobra"
)

var quarantineCmd = &cobra.Command{
	Use:   "quarantine",
	Short: "Manage quarantined files",
}

var quarantineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all quarantined files",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := getConfig()
		sdb, err := store.New(cfg.DBPath)
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
	},
}

var quarantineRestoreCmd = &cobra.Command{
	Use:   "restore <id>",
	Short: "Restore a quarantined file to its original location",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := getConfig()
		sdb, err := store.New(cfg.DBPath)
		if err != nil {
			return err
		}
		defer sdb.Close()

		var id int64
		if _, err := fmt.Sscanf(args[0], "%d", &id); err != nil {
			return fmt.Errorf("invalid ID: %s", args[0])
		}

		rec, err := sdb.GetQuarantineByID(id)
		if err != nil {
			return fmt.Errorf("quarantine record not found: %w", err)
		}

		srcPath := rec.QuarantinePath
		if srcPath == "" {
			// Older records predate the stored QuarantinePath; fall back to
			// locating the file by name under the quarantine directory.
			srcPath = filepath.Join(cfg.QuarantinePath, rec.FileName)
			if _, err := os.Stat(srcPath); err != nil {
				possiblePaths, _ := filepath.Glob(filepath.Join(cfg.QuarantinePath, "*", rec.FileName))
				if len(possiblePaths) > 0 {
					srcPath = possiblePaths[0]
				} else {
					return fmt.Errorf("quarantined file not found on disk")
				}
			}
		}

		if _, err := os.Stat(srcPath); err != nil {
			return fmt.Errorf("quarantined file not found on disk: %w", err)
		}

		// Move the file back to its original location. Prefer a rename
		// (reverse of the quarantine move); fall back to copy+delete only if
		// the rename fails across filesystems.
		if err := os.Rename(srcPath, rec.OriginalPath); err != nil {
			if copyErr := copyFile(srcPath, rec.OriginalPath); copyErr != nil {
				return fmt.Errorf("restoring file: %w", copyErr)
			}
			if removeErr := os.Remove(srcPath); removeErr != nil {
				return fmt.Errorf("restoring file: could not remove quarantined copy: %w", removeErr)
			}
		}

		os.Chmod(rec.OriginalPath, 0644)
		sdb.RemoveQuarantine(id)

		fmt.Printf("Restored: %s → %s\n", rec.FileName, rec.OriginalPath)
		return nil
	},
}

func init() {
	quarantineCmd.AddCommand(quarantineListCmd)
	quarantineCmd.AddCommand(quarantineRestoreCmd)
	rootCmd.AddCommand(quarantineCmd)
}
