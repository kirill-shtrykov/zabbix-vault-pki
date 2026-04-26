package vault_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kirill-shtrykov/zabbix-vault-pki/pkg/config"
	"github.com/kirill-shtrykov/zabbix-vault-pki/pkg/vault"
)

func TestNewClientSuccess(t *testing.T) {
	t.Parallel()

	const token = "test-token"

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("method = %s, want PUT", r.Method)
		}

		if r.URL.Path != "/v1/auth/approle/login" {
			t.Fatalf("path = %s, want /v1/auth/approle/login", r.URL.Path)
		}

		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}

		if got, want := body["role_id"], "role-id"; got != want {
			t.Fatalf("role_id = %q, want %q", got, want)
		}

		if got, want := body["secret_id"], "secret-id"; got != want {
			t.Fatalf("secret_id = %q, want %q", got, want)
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{
				"client_token": token,
			},
		}); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer server.Close()

	cfg := &config.Config{
		Address:       server.URL,
		RoleID:        "role-id",
		SecretID:      "secret-id",
		TLSSkipVerify: true,
	}

	client, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if got, want := client.Token(), token; got != want {
		t.Fatalf("Token() = %q, want %q", got, want)
	}
}

func TestNewClientReturnsAuthenticationErrorForEmptyAuth(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(map[string]any{}); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer server.Close()

	cfg := &config.Config{
		Address:       server.URL,
		RoleID:        "role-id",
		SecretID:      "secret-id",
		TLSSkipVerify: true,
	}

	_, err := vault.NewClient(cfg)
	if err == nil {
		t.Fatal("NewClient() error = nil, want non-nil")
	}

	if !errors.Is(err, vault.ErrAuthenticationError) {
		t.Fatalf("error = %v, want %v", err, vault.ErrAuthenticationError)
	}
}
