package vault

import (
	"errors"
	"fmt"

	"github.com/hashicorp/vault/api"
	"github.com/kirill-shtrykov/zabbix-vault-pki/pkg/config"
)

var ErrAuthenticationError = errors.New("vault return empty response")

func NewClient(cfg *config.Config) (*api.Client, error) {
	defaultConfig := api.DefaultConfig()
	defaultConfig.Address = cfg.Address

	if err := defaultConfig.ConfigureTLS(&api.TLSConfig{
		Insecure: cfg.TLSSkipVerify,
	}); err != nil {
		return nil, fmt.Errorf("failed to configure TLS: %w", err)
	}

	client, err := api.NewClient(defaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	loginData := map[string]interface{}{
		"role_id":   cfg.RoleID,
		"secret_id": cfg.SecretID,
	}

	secret, err := client.Logical().Write("auth/approle/login", loginData)
	if err != nil {
		return nil, fmt.Errorf("failed to login with AppRole: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return nil, ErrAuthenticationError
	}

	client.SetToken(secret.Auth.ClientToken)

	return client, nil
}
