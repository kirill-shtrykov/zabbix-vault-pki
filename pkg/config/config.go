package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsimple"
)

const (
	addrHelpText = `
Address of the Vault server.
Overrides the VAULT_ADDR environment variable if set.
Default = "https://127.0.0.1:8200"
`
	roleHelpText = `
RoleID is an identifier that selects the AppRole against which the other credentials are evaluated.
Overrides the VAULT_ROLE_ID environment variable if set.
Default = ""
`
	// #nosec G101
	secretHelpText = `
SecretID is a credential that is required by default for any login (via secret_id) and is intended to always be secret.
Overrides the VAULT_SECRET_ID environment variable if set.
Default = ""
`
	configHelpText = `
Path to config file.
Overrides the VAULT_CONFIG environment variable if set.
Default = "/etc/zabbix-vault-pki/config.hcl"
`
)

var ErrRequiredField = errors.New("required fields")

type Config struct {
	Address  string `hcl:"address,optional"`
	RoleID   string `hcl:"role_id,optional"`
	SecretID string `hcl:"secret_id,optional"`
}

// Retrieves the value of the environment variable named by the `key`.
// It returns the value if variable present and value not empty.
// Otherwise it returns string value `def`.
func stringFromEnv(key string, def string) string {
	if v := os.Getenv(key); v != "" {
		return strings.TrimSpace(v)
	}

	return def
}

func Load() (*Config, error) {
	configFile := "/etc/zabbix-vault-pki/config.hcl"
	cfg := Config{
		Address:  stringFromEnv("VAULT_ADDR", ""),
		RoleID:   stringFromEnv("VAULT_ROLE_ID", ""),
		SecretID: stringFromEnv("VAULT_SECRET_ID", ""),
	}

	flag.StringVar(&cfg.Address, "address", cfg.Address, strings.TrimSpace(addrHelpText))
	flag.StringVar(&cfg.RoleID, "role-id", cfg.RoleID, strings.TrimSpace(roleHelpText))
	flag.StringVar(&cfg.SecretID, "secret-id", cfg.SecretID, strings.TrimSpace(secretHelpText))
	flag.StringVar(&configFile, "config", configFile, strings.TrimSpace(configHelpText))
	flag.Parse()

	if _, err := os.Stat(configFile); err == nil {
		hclCfg := Config{}
		if err := hclsimple.DecodeFile(configFile, nil, &hclCfg); err != nil {
			return nil, fmt.Errorf("failed to read HCL config %s: %w", configFile, err)
		}

		if cfg.Address == "" {
			cfg.Address = hclCfg.Address
		}

		if cfg.RoleID == "" {
			cfg.RoleID = hclCfg.RoleID
		}

		if cfg.SecretID == "" {
			cfg.SecretID = hclCfg.SecretID
		}
	}

	if cfg.Address == "" {
		cfg.Address = "https://127.0.0.1:8200"
	}

	if cfg.RoleID == "" || cfg.SecretID == "" {
		return nil, fmt.Errorf("%w: role-id and secret-id are required, got: %+v", ErrRequiredField, cfg)
	}

	return &cfg, nil
}
