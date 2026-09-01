package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

const (
	Version = "0.1.0"
	AppName = "calypso"
	Tagline = "Defend before you open."
)

type Config struct {
	VirusTotalAPIKey string   `mapstructure:"virustotal_api_key"`
	QuarantinePath   string   `mapstructure:"quarantine_path"`
	DBPath           string   `mapstructure:"db_path"`
	RulesPath        string   `mapstructure:"rules_path"`
	ExcludedPaths    []string `mapstructure:"excluded_paths"`
	Engines          Engines  `mapstructure:"engines"`
	Theme            string   `mapstructure:"theme"`
	DeepScanConfirmed bool   `mapstructure:"deep_scan_confirmed"`
}

type Engines struct {
	Hash      bool `mapstructure:"hash"`
	FileType  bool `mapstructure:"file_type"`
	ClamAV    bool `mapstructure:"clamav"`
	Yara      bool `mapstructure:"yara"`
	Heuristic bool `mapstructure:"heuristic"`
	Cloud     bool `mapstructure:"cloud"`
}

func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".calypso"
	}
	return filepath.Join(home, ".calypso")
}

func DefaultDBPath() string {
	return filepath.Join(DefaultConfigPath(), "calypso.db")
}

func DefaultQuarantinePath() string {
	return filepath.Join(DefaultConfigPath(), "quarantine")
}

func DefaultRulesPath() string {
	return filepath.Join(DefaultConfigPath(), "rules")
}

func Load() (*Config, error) {
	cfgDir := DefaultConfigPath()

	if err := os.MkdirAll(cfgDir, 0755); err != nil {
		return nil, fmt.Errorf("creating config dir: %w", err)
	}

	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(cfgDir)

	v.SetDefault("virustotal_api_key", "")
	v.SetDefault("quarantine_path", DefaultQuarantinePath())
	v.SetDefault("db_path", DefaultDBPath())
	v.SetDefault("rules_path", DefaultRulesPath())
	v.SetDefault("excluded_paths", []string{})
	v.SetDefault("theme", "default")
	v.SetDefault("deep_scan_confirmed", false)
	v.SetDefault("engines.hash", true)
	v.SetDefault("engines.file_type", true)
	v.SetDefault("engines.clamav", true)
	v.SetDefault("engines.yara", true)
	v.SetDefault("engines.heuristic", true)
	v.SetDefault("engines.cloud", false)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
		if err := v.WriteConfigAs(filepath.Join(cfgDir, "config.yaml")); err != nil {
			return nil, fmt.Errorf("writing default config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	return &cfg, nil
}
