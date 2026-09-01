package cmd

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/calypso-scanner/calypso/internal/store"
	"github.com/spf13/cobra"
)

var blocklistCmd = &cobra.Command{
	Use:   "blocklist",
	Short: "Manage the known-bad hash blocklist",
}

var blocklistAddCmd = &cobra.Command{
	Use:   "add <sha256>",
	Short: "Add a SHA-256 hash to the blocklist",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		hash := strings.ToLower(strings.TrimSpace(args[0]))
		if _, err := hex.DecodeString(hash); err != nil || len(hash) != 64 {
			return fmt.Errorf("invalid SHA-256 hash (expected 64 hex characters): %s", args[0])
		}

		cfg := getConfig()
		sdb, err := store.New(cfg.DBPath)
		if err != nil {
			return err
		}
		defer sdb.Close()

		if err := sdb.AddToBlocklist(hash, "", "malicious", "manual"); err != nil {
			return fmt.Errorf("adding to blocklist: %w", err)
		}
		fmt.Printf("Added %s to blocklist.\n", hash)
		return nil
	},
}

var blocklistListCmd = &cobra.Command{
	Use:   "list",
	Short: "List known-bad hashes in the blocklist",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := getConfig()
		sdb, err := store.New(cfg.DBPath)
		if err != nil {
			return err
		}
		defer sdb.Close()

		entries := sdb.ListBlocklist()
		if len(entries) == 0 {
			fmt.Println("Blocklist is empty.")
			return nil
		}

		for _, e := range entries {
			fmt.Printf("%s  %s  (source: %s)\n", e.SHA256, e.Verdict, e.Source)
		}
		return nil
	},
}

func init() {
	blocklistCmd.AddCommand(blocklistAddCmd)
	blocklistCmd.AddCommand(blocklistListCmd)
	rootCmd.AddCommand(blocklistCmd)
}
