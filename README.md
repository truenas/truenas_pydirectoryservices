# TrueNAS Directory Services Libraries

CPython extensions and utilities for TrueNAS directory services integration.

## Packages

### truenas_pynss

Direct NSS (Name Service Switch) lookups via dlopen'd NSS modules.
Bypasses nsswitch.conf to query FILES, SSS, or WINBIND backends directly.

- `getpwnam`, `getpwuid` -- passwd lookups
- `getgrnam`, `getgrgid` -- group lookups
- `iterpw`, `itergrp` -- iteration with per-backend locking for thread safety
- Context manager support on iterators

### truenas_pykrb5

MIT Kerberos 5 bindings.

- Keytab read/write: `get_keytab`, `Keytab.add_entry`, `Keytab.remove_entry`, `Keytab.as_bytes`
- Credential cache access: `get_ccache`, `Ccache.iter_credentials`, `Ccache.kdestroy`
- Credential acquisition: `get_init_creds_keytab`, `get_init_creds_password`
- Enums: `KRB5EncType`, `KRB5ErrCode`, `KRB5PrincipalType`, `KRB5TktFlags`
- Struct types: `KeyInfo`, `PrincipalInfo`, `AddressInfo`, `AuthDataInfo`

### truenas_krb5conf_pyutils

Pure Python module for generating and validating krb5.conf files.

- `KRB5Conf` -- builder with `add_libdefaults`, `add_appdefaults`, `add_realms`, `generate`, `write`
- Parameter validation against typed descriptors

## Build

Requires: `python3-dev`, `libkrb5-dev`

```sh
# Debian package
dpkg-buildpackage -us -uc -b

# Development
python3 setup.py build_ext --inplace
python3 -m pytest tests/
```

## License

LGPL-3.0-or-later
