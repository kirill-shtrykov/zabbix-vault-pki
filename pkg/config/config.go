package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsimple"
)

const (
	defaultAddress = "https://127.0.0.1:8200"
	addrHelpText   = `
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
	defaultConfigPath = "/etc/zabbix-vault-pki/config.hcl"
	configHelpText    = `
Path to config file.
Overrides the VAULT_CONFIG environment variable if set.
Default = "/etc/zabbix-vault-pki/config.hcl"
`
	revokedHelpText = `
Check revoked certificates.
Overrides the VAULT_REVOKED environment variable if set.
Default = false
`
	tlsSkipVerifyHelpText = `
Disable verification for all TLS certificates.
Use with caution. Disabling TLS certificate verification decreases the security
of data transmissions to and from the Vault server.
Overrides the VAULT_SKIP_VERIFY environment variable if set.
Default = false
`
)

var (
	ErrRequiredField = errors.New("required fields")
	ErrInvalidFlags  = errors.New("invalid flags")
)

// stringFromEnv retrieves the value of the environment variable named by the `key`.
// It returns the value if variable present and value not empty.
// Otherwise it returns string value `def`.
func stringFromEnv(key string, def string) string {
	if v := os.Getenv(key); v != "" {
		return strings.TrimSpace(v)
	}

	return def
}

// boolFromEnv retrieves the value of the environment variable named by the `key`.
// It returns the boolean value of the variable if present and valid.
// Otherwise, it returns the default value `def`.
func boolFromEnv(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		parsed, err := strconv.ParseBool(strings.TrimSpace(v))
		if err == nil {
			return parsed
		}
	}

	return def
}

func isFlagPassed(fs *flag.FlagSet, name string) bool {
	found := false

	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})

	return found
}

type Config struct {
	Address       string `hcl:"address,optional"`
	RoleID        string `hcl:"role_id,optional"`
	SecretID      string `hcl:"secret_id,optional"`
	Revoked       bool   `hcl:"revoked,optional"`
	TLSSkipVerify bool   `hcl:"tls_skip_verify,optional"`
}

func (c *Config) Validate() error {
	if c.RoleID == "" {
		return fmt.Errorf("%w: role ID is required", ErrRequiredField)
	}

	if c.SecretID == "" {
		return fmt.Errorf("%w: secret ID is required", ErrRequiredField)
	}

	return nil
}

func fromHCL(path string) (Config, error) {
	var cfg Config

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return Config{}, nil
		}

		return Config{}, fmt.Errorf("stat config: %w", err)
	}

	if err := hclsimple.DecodeFile(path, nil, &cfg); err != nil {
		return Config{}, fmt.Errorf("failed to read HCL config %s: %w", path, err)
	}

	return cfg, nil
}

func newFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Global flags:\n")
		fs.PrintDefaults()
	}

	return fs
}

func registerFlags(
	fs *flag.FlagSet,
	address, roleID, secretID, configPath *string,
	revoked, tlsSkipVerify *bool,
) {
	fs.StringVar(address, "address", stringFromEnv("VAULT_ADDR", ""), addrHelpText)
	fs.StringVar(roleID, "role-id", stringFromEnv("VAULT_ROLE_ID", ""), roleHelpText)
	fs.StringVar(secretID, "secret-id", stringFromEnv("VAULT_SECRET_ID", ""), secretHelpText)
	fs.StringVar(configPath, "config", stringFromEnv("VAULT_CONFIG", defaultConfigPath), configHelpText)
	fs.BoolVar(revoked, "revoked", false, revokedHelpText)
	fs.BoolVar(tlsSkipVerify, "tls-skip-verify", false, tlsSkipVerifyHelpText)
}

func applyStringOverrides(cfg *Config, address, roleID, secretID string) {
	if address != "" {
		cfg.Address = address
	}

	if roleID != "" {
		cfg.RoleID = roleID
	}

	if secretID != "" {
		cfg.SecretID = secretID
	}
}

func applyBoolOverrides(cfg *Config, fs *flag.FlagSet, revoked, tlsSkipVerify bool) {
	cfg.Revoked = boolFromEnv("VAULT_REVOKED", cfg.Revoked)
	cfg.TLSSkipVerify = boolFromEnv("VAULT_SKIP_VERIFY", cfg.TLSSkipVerify)

	if isFlagPassed(fs, "revoked") {
		cfg.Revoked = revoked
	}

	if isFlagPassed(fs, "tls-skip-verify") {
		cfg.TLSSkipVerify = tlsSkipVerify
	}
}

func Load() (Config, []string, error) {
	var (
		configPath    string
		address       string
		roleID        string
		secretID      string
		revoked       bool
		tlsSkipVerify bool
	)

	fs := newFlagSet()
	registerFlags(fs, &address, &roleID, &secretID, &configPath, &revoked, &tlsSkipVerify)

	if err := fs.Parse(os.Args[1:]); err != nil {
		return Config{}, nil, fmt.Errorf("%w: %w", ErrInvalidFlags, err)
	}

	cfg, err := fromHCL(configPath)
	if err != nil {
		return Config{}, nil, fmt.Errorf("failed to read HCL: %w", err)
	}

	applyStringOverrides(&cfg, address, roleID, secretID)
	applyBoolOverrides(&cfg, fs, revoked, tlsSkipVerify)

	if cfg.Address == "" {
		cfg.Address = defaultAddress
	}

	return cfg, fs.Args(), nil
}
