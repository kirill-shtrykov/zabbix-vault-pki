# zabbix-vault-pki
Go application that retrieves certificate information from the HashiCorp Vault PKI backend and exposes it in a format compatible with Zabbix monitoring. It supports low-level discovery (LLD) to automatically detect available certificates and provides metadata for monitoring and alerting.

---

## Features

- Discover certificate serial numbers and common names from Vault PKI (LLD JSON output)
- Return expiration timestamp for a given serial (UNIX seconds)
- Configurable via CLI flags, HCL config file, or environment variables
  Priority: **flags > HCL file > env vars**
- AppRole authentication support for Vault
- Small single-binary CLI suitable for Zabbix `UserParameter`

---

## Install
DEB/RPM packages for x64 could be found in [GitHub Releases](https://github.com/kirill-shtrykov/zabbix-vault-pki/releases).

Manual build and installation:
```bash
git clone https://github.com/kirill-shtrykov/zabbix-vault-pki.git
cd zabbix-vault-pki
go build ./cmd/zabbix-vault-pki
# or: go install ./cmd/zabbix-vault-pki
```
Also [Taskfile](https://taskfile.dev/) is included.

---

## Usage

Global flags (can be provided before the command):

```
-address    Vault address (default: https://127.0.0.1:8200)
-role-id    AppRole RoleID
-secret-id  AppRole SecretID
-config     Path to HCL config (default: /etc/zabbix-vault-pki/config.hcl)
```

Commands:

- `discover` — print Zabbix LLD JSON on stdout
  Example:

  ```bash
  ./zabbix-vault-pki -address=https://vault.example.com discover
  ```

  Output:

  ```json
  {"data":[{"{#SN":"aa:bb:cc:..."}]}
  ```

- `expiry <serial>` — print `notAfter` as UNIX timestamp (seconds) for the given serial
  Example:

  ```bash
  ./zabbix-vault-pki expiry 0f:d5:4a:...
  ```

  Output:

  ```
  1717459200
  ```

Notes:

- Prefer passing credentials with flags or env vars for automation: `VAULT_ADDR`, `VAULT_ROLE_ID`, `VAULT_SECRET_ID`, `VAULT_CONFIG`.
- HCL config is optional and fields are optional. Flags override HCL values.

---

## HCL example (`/etc/zabbix-vault-pki/config.hcl`)

All fields are optional.

```hcl
address   = "https://vault.example.com"
role_id   = "your-role-id"
secret_id = "your-secret-id"
```

---

## Examples & templates

Examples and ready-to-use artifacts are under `examples/`:

```
examples/
├─ userparameter/          # Zabbix Agent UserParameter files
│  └─ zabbix-vault-pki.conf
└─ template/               # Zabbix template (YAML) for import
   └─ zabbix-template-vault-pki.yaml
```

---

## Library / Code layout

- `cmd/` — CLI entrypoint
- `pkg/config` — configuration loader (flags > HCL > env)
- `pkg/vault` — Vault client + AppRole login helper
- `internal/monitor` — logic to list certs and fetch certificate info

---

## Integration notes

- Some Vault PKI setups use `no_store=true` — in that case Vault will not store issued certs,
so `pki/cert/<serial>` will return no value even if `LIST pki/certs` shows serials.

---

## Contributing

Contributions, issues and feature requests are welcome.
Please open an issue or a PR on the project repository:
[https://github.com/kirill-shtrykov/zabbix-vault-pki](https://github.com/kirill-shtrykov/zabbix-vault-pki)

---

## License

[MIT](LICENSE)
