Name:           zabbix-vault-pki
Version:        VERSION
Release:        1%{?dist}
Summary:        Zabbix monitoring tool for Vault PKI
License:        MIT
URL:            https://github.com/kirill-shtrykov/zabbix-vault-pki
Group:          Utilities
BuildArch:      x86_64
Packager:       Kirill Shtrykov <kirill@shtrykov.com>

%description
Go application that retrieves certificate information from
HashiCorp Vault PKI backend and exposes it in a format
compatible with Zabbix monitoring.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/zabbix-vault-pki
install -m 0755 %{_sourcedir}/zabbix-vault-pki %{buildroot}/usr/bin/
install -m 0644 %{_sourcedir}/config.hcl %{buildroot}/etc/zabbix-vault-pki/config.hcl

%files
/usr/bin/zabbix-vault-pki
/etc/zabbix-vault-pki/config.hcl

%changelog
* Thu Mar 12 2026 Kirill Shtrykov<kirill@shtrykov.com> - VERSION-1
- Initial package
