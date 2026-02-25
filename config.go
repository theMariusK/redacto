package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// generatePlaceholder creates a deterministic same-length placeholder from the
// original string using a SHA-256 hash, encoded as hex. The hash is repeated
// as needed to match the original length.
func generatePlaceholder(original string) string {
	h := sha256.Sum256([]byte(original))
	hexStr := hex.EncodeToString(h[:])
	// Repeat hex string to cover any length
	for len(hexStr) < len(original) {
		hexStr += hexStr
	}
	return hexStr[:len(original)]
}

type Rule struct {
	Original    string `yaml:"original"`
	Placeholder string `yaml:"placeholder"`
}

type EnvRule struct {
	Name        string `yaml:"name"`
	Placeholder string `yaml:"placeholder"`
}

type Config struct {
	Rules          []Rule   `yaml:"rules"`
	EnvRules       []EnvRule `yaml:"env_rules"`
	SkipExtensions []string `yaml:"skip_extensions"`
	SkipPaths      []string `yaml:"skip_paths"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if len(cfg.Rules) == 0 && len(cfg.EnvRules) == 0 {
		return nil, fmt.Errorf("config has no rules")
	}

	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if len(r.Original) == 0 {
			return nil, fmt.Errorf("rule %d: original must be non-empty", i)
		}
		if len(r.Placeholder) == 0 {
			r.Placeholder = generatePlaceholder(r.Original)
		}
		if len(r.Original) != len(r.Placeholder) {
			return nil, fmt.Errorf("rule %d: original (%d bytes) and placeholder (%d bytes) must be the same length",
				i, len(r.Original), len(r.Placeholder))
		}
	}

	for i, r := range cfg.EnvRules {
		if len(r.Name) == 0 || len(r.Placeholder) == 0 {
			return nil, fmt.Errorf("env_rule %d: name and placeholder must be non-empty", i)
		}
	}

	return &cfg, nil
}
