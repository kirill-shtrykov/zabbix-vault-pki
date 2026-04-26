# zabbix-vault-pki configuration file
#
# This file defines connection parameters used by the zabbix-vault-pki
# CLI tool to authenticate and communicate with the HashiCorp Vault PKI backend.
#
# Configuration priority (highest to lowest):
#   1. CLI flags
#   2. Environment variables
#   3. HCL configuration file
#
# Default config location:
#   /etc/zabbix-vault-pki/config.hcl
#
# Environment variables supported:
#   VAULT_ADDR
#   VAULT_ROLE_ID
#   VAULT_SECRET_ID
#   VAULT_REVOKED
#   VAULT_SKIP_VERIFY
#

# Vault address
# address = "http://127.0.0.1:8200"

# Vault AppRole RoleID
# role_id =

# Vault AppRole SecretID
# secret_id =

# Include revoked certificates in discovery output
# revoked = false

# Disable TLS certificate verification for Vault connection.
# Use only for diagnostics or legacy environments.
# tls_skip_verify = false
