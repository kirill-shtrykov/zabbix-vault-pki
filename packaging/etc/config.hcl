# zabbix-vault-pki configuration file
#
# This file defines connection parameters used by the zabbix-vault-pki
# CLI tool to authenticate and communicate with the HashiCorp Vault PKI backend.
#
# Configuration priority (highest to lowest):
#   1. CLI flags
#   2. HCL configuration file
#   3. Environment variables
#
# Default config location:
#   /etc/zabbix-vault-pki/config.hcl
#
# Environment variables supported:
#   VAULT_ADDR
#   VAULT_ROLE_ID
#   VAULT_SECRET_ID
#

# Vault address
# address = "http://127.0.0.1:8200"

# Vault AppRole RoleID
# role_id =

# Vault AppRole SecretID
# secret_id =
