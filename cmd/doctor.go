package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/calypso-scanner/calypso/internal/config"
	"github.com/calypso-scanner/calypso/internal/ui"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system health and dependencies",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDoctor()
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor() error {
	cfg := getConfig()

	fmt.Println(ui.TitleStyle.Render("  CALYPSO DOCTOR"))
	fmt.Println()

	checks := []struct {
		name    string
		check   func() (bool, string)
		fixHint string
	}{
		{"ClamAV (clamscan)", checkClamAV, "Install ClamAV: https://www.clamav.net/downloads"},
		{"ClamAV updater (freshclam)", checkFreshclam, "Install ClamAV with freshclam component"},
		{"YARA rules", func() (bool, string) {
			return checkYARARules(cfg.RulesPath)
		}, "Run: calypso update"},
		{"Config file", func() (bool, string) {
			return checkConfigFile()
		}, "Config will be created automatically on first run"},
		{"Database", func() (bool, string) {
			return checkDatabase(cfg.DBPath)
		}, "Database will be created automatically"},
		{"Quarantine directory", func() (bool, string) {
			return checkQuarantineDir(cfg.QuarantinePath)
		}, "Directory will be created when needed"},
		{"VirusTotal API key", func() (bool, string) {
			return checkVTKey(cfg.VirusTotalAPIKey)
		}, "Set in ~/.calypso/config.yaml or use: calypso config"},
	}

	allOK := true
	for _, c := range checks {
		ok, detail := c.check()
		icon := ui.SuccessStyle.Render("OK")
		status := ""

		if !ok {
			icon = ui.WarnStyle.Render("!!")
			allOK = false
		}

		fmt.Printf("  %-4s %-28s %s", icon, c.name, status)
		if detail != "" {
			fmt.Printf("  %s", ui.SubtleStyle.Render(detail))
		}
		fmt.Println()
	}

	fmt.Println()
	if allOK {
		fmt.Println(ui.SuccessStyle.Render("  All checks passed. Calypso is ready."))
	} else {
		fmt.Println(ui.WarnStyle.Render("  Some checks failed. Install missing dependencies for full functionality."))
	}

	return nil
}

func checkClamAV() (bool, string) {
	path, err := exec.LookPath("clamscan")
	if err != nil {
		return false, ""
	}
	return true, path
}

func checkFreshclam() (bool, string) {
	path, err := exec.LookPath("freshclam")
	if err != nil {
		return false, ""
	}
	return true, path
}

func checkYARARules(rulesPath string) (bool, string) {
	count := 0
	filepath.WalkDir(rulesPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".yar") {
			count++
		}
		return nil
	})

	if count == 0 {
		return false, "No rules found"
	}
	return true, fmt.Sprintf("%d rules found", count)
}

func checkConfigFile() (bool, string) {
	cfgPath := filepath.Join(config.DefaultConfigPath(), "config.yaml")
	if _, err := os.Stat(cfgPath); err != nil {
		return false, "Not created yet"
	}
	return true, cfgPath
}

func checkDatabase(dbPath string) (bool, string) {
	if _, err := os.Stat(dbPath); err != nil {
		return false, "Not created yet"
	}
	return true, dbPath
}

func checkQuarantineDir(qPath string) (bool, string) {
	if _, err := os.Stat(qPath); err != nil {
		return false, "Not created yet"
	}
	return true, qPath
}

func checkVTKey(key string) (bool, string) {
	if key == "" {
		return false, "Not configured (optional)"
	}
	return true, "Configured"
}
