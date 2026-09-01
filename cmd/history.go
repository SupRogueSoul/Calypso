package cmd

import (
	"fmt"

	"github.com/calypso-scanner/calypso/internal/store"
	"github.com/spf13/cobra"
)

var historyShowID int64

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "View scan history",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := getConfig()
		sdb, err := store.New(cfg.DBPath)
		if err != nil {
			return err
		}
		defer sdb.Close()

		if historyShowID > 0 {
			rec, err := sdb.GetHistoryByID(historyShowID)
			if err != nil {
				return fmt.Errorf("scan record not found: %w", err)
			}
			fmt.Printf("Scan #%d\n", rec.ID)
			fmt.Printf("  File:     %s\n", rec.FilePath)
			fmt.Printf("  SHA-256:  %s\n", rec.SHA256)
			fmt.Printf("  MD5:      %s\n", rec.MD5)
			fmt.Printf("  Verdict:  %s\n", rec.Verdict)
			fmt.Printf("  Score:    %.0f/100\n", rec.Score)
			fmt.Printf("  Engines:  %s\n", rec.Engines)
			fmt.Printf("  Time:     %s\n", rec.Timestamp.Format("2006-01-02 15:04:05"))
			return nil
		}

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
	},
}

func init() {
	historyCmd.Flags().Int64Var(&historyShowID, "show", 0, "Show details for a specific scan ID")
	rootCmd.AddCommand(historyCmd)
}
