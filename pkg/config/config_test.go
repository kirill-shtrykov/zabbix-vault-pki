package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kirill-shtrykov/zabbix-vault-pki/pkg/config"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     config.Config
		wantErr bool
	}{
		{
			name: "valid",
			cfg: config.Config{
				Address:  "https://vault.example.com",
				RoleID:   "role-id",
				SecretID: "secret-id",
			},
		},
		{
			name: "missing role id",
			cfg: config.Config{
				SecretID: "secret-id",
			},
			wantErr: true,
		},
		{
			name: "missing secret id",
			cfg: config.Config{
				RoleID: "role-id",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("Validate() error = nil, want non-nil")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}
		})
	}
}

func TestLoadPrecedence(t *testing.T) {
	configPath := writeConfigFile(t, `
address = "https://hcl.example.com"
role_id = "hcl-role"
secret_id = "hcl-secret"
revoked = false
tls_skip_verify = false
`)

	restore := setArgs(t, []string{
		"zabbix-vault-pki",
		"-config", configPath,
		"-address", "https://flag.example.com",
		"-revoked=true",
		"discover",
	})
	defer restore()

	t.Setenv("VAULT_ROLE_ID", "env-role")
	t.Setenv("VAULT_SECRET_ID", "env-secret")
	t.Setenv("VAULT_SKIP_VERIFY", "true")

	cfg, args, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got, want := cfg.Address, "https://flag.example.com"; got != want {
		t.Fatalf("Address = %q, want %q", got, want)
	}

	if got, want := cfg.RoleID, "env-role"; got != want {
		t.Fatalf("RoleID = %q, want %q", got, want)
	}

	if got, want := cfg.SecretID, "env-secret"; got != want {
		t.Fatalf("SecretID = %q, want %q", got, want)
	}

	if !cfg.Revoked {
		t.Fatal("Revoked = false, want true")
	}

	if !cfg.TLSSkipVerify {
		t.Fatal("TLSSkipVerify = false, want true")
	}

	if len(args) != 1 || args[0] != "discover" {
		t.Fatalf("args = %v, want [discover]", args)
	}
}

//nolint:paralleltest // Mutates process-wide os.Args for Load().
func TestLoadReturnsDefaultAddress(t *testing.T) {
	restore := setArgs(t, []string{"zabbix-vault-pki", "version"})
	defer restore()

	cfg, args, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got, want := cfg.Address, "https://127.0.0.1:8200"; got != want {
		t.Fatalf("Address = %q, want %q", got, want)
	}

	if len(args) != 1 || args[0] != "version" {
		t.Fatalf("args = %v, want [version]", args)
	}
}

//nolint:paralleltest // Mutates process-wide os.Args for Load().
func TestLoadInvalidFlags(t *testing.T) {
	restore := setArgs(t, []string{"zabbix-vault-pki", "-unknown"})
	defer restore()

	_, _, err := config.Load()
	if err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}

	if !errors.Is(err, config.ErrInvalidFlags) {
		t.Fatalf("error = %v, want ErrInvalidFlags", err)
	}
}

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.hcl")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	return path
}

func setArgs(t *testing.T, args []string) func() {
	t.Helper()

	original := os.Args
	os.Args = args

	return func() {
		os.Args = original
	}
}
