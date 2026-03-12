package vault

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	"github.com/kirill-shtrykov/zabbix-vault-pki/pkg/config"
)

func NewClient(cfg *config.Config) (*api.Client, error) {
	defaultConfig := api.DefaultConfig()
	defaultConfig.Address = cfg.Address

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

	client.SetToken(secret.Auth.ClientToken)

	return client, nil
}
