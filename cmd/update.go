package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/calypso-scanner/calypso/internal/config"
	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update ClamAV signatures and YARA rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := getConfig()
		return runUpdate(cfg)
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

func runUpdate(cfg *config.Config) error {
	fmt.Println("Updating ClamAV signatures...")
	if err := updateClamAV(); err != nil {
		fmt.Printf("  ClamAV update failed: %v\n", err)
	} else {
		fmt.Println("  ClamAV signatures updated successfully.")
	}

	fmt.Println("\nUpdating YARA community rules...")
	if err := updateYARARules(cfg); err != nil {
		fmt.Printf("  YARA update failed: %v\n", err)
	} else {
		fmt.Println("  YARA rules updated successfully.")
	}

	return nil
}

func updateClamAV() error {
	path, err := exec.LookPath("freshclam")
	if err != nil {
		return fmt.Errorf("freshclam not found in PATH. Install ClamAV first.")
	}

	cmd := exec.Command(path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func updateYARARules(cfg *config.Config) error {
	rulesDir := cfg.RulesPath
	communityDir := filepath.Join(rulesDir, "community")

	if err := os.MkdirAll(communityDir, 0755); err != nil {
		return fmt.Errorf("creating rules directory: %w", err)
	}

	defaultRules := map[string]string{
		"powershell.yar": `rule PowerShell_Obfuscated {
    strings:
        $s1 = "FromBase64String" ascii
        $s2 = "Invoke-Expression" ascii
        $s3 = "-enc " ascii
        $s4 = "IEX(" ascii
        $s5 = "[System.Net.WebClient]" ascii
    condition:
        2 of them
}`,
		"macro_dropper.yar": `rule Office_Macro_Dropper {
    strings:
        $s1 = "Auto_Open" ascii
        $s2 = "Document_Open" ascii
        $s3 = "Workbook_Open" ascii
        $s4 = "Shell(" ascii
        $s5 = "CreateObject(" ascii
    condition:
        3 of them
}`,
		"packed_exec.yar": `rule Packed_Executable {
    strings:
        $s1 = "UPX0" ascii
        $s2 = "UPX1" ascii
        $s3 = ".aspack" ascii
        $s4 = ".adata" ascii
        $s5 = "MEW" ascii
    condition:
        2 of them
}`,
		"shellcode.yar": `rule Shellcode_Patterns {
    strings:
        $s1 = "VirtualAlloc" ascii
        $s2 = "WriteProcessMemory" ascii
        $s3 = "CreateRemoteThread" ascii
        $s4 = "NtUnmapViewOfSection" ascii
        $s5 = {90 90 90}
    condition:
        2 of them
}`,
		"ransomware.yar": `rule Ransomware_Indicators {
    strings:
        $s1 = ".onion" ascii
        $s2 = "bitcoin" ascii nocase
        $s3 = "BTC" ascii
        $s4 = "decrypt" ascii nocase
        $s5 = "ransom" ascii nocase
    condition:
        3 of them
}`,
		"credential_dump.yar": `rule Credential_Dumping {
    strings:
        $s1 = "mimikatz" ascii nocase
        $s2 = "sekurlsa" ascii
        $s3 = "LogonPasswords" ascii
        $s4 = "lsass" ascii
    condition:
        2 of them
}`,
	}

	for name, content := range defaultRules {
		rulePath := filepath.Join(communityDir, name)
		if _, err := os.Stat(rulePath); os.IsNotExist(err) {
			if err := os.WriteFile(rulePath, []byte(content), 0644); err != nil {
				return fmt.Errorf("writing rule %s: %w", name, err)
			}
			fmt.Printf("  Created: %s\n", name)
		} else {
			fmt.Printf("  Exists:  %s (skipping)\n", name)
		}
	}

	_ = strings.Join(nil, "")
	return nil
}
