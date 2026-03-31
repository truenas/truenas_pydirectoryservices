# SPDX-License-Identifier: LGPL-3.0-or-later

import ipaddress
import os

from copy import deepcopy
from enum import auto, Enum
from tempfile import NamedTemporaryFile

from .constants import (
    APPDEFAULTS_PARAMS,
    KRB5Realm,
    LIBDEFAULTS_PARAMS,
)

KRB5_VALUE_BEGIN = '{'
KRB5_VALUE_END = '}'


def format_server(address: str | None) -> str | None:
    """Format a server address for use in krb5.conf.

    IPv6 addresses are enclosed in brackets.
    """
    if address is None:
        return None

    address = address.strip()
    try:
        ipaddress.IPv6Address(address)
        return f'[{address}]'
    except ValueError:
        return address


class KRB5ConfSection(Enum):
    LIBDEFAULTS = auto()
    REALMS = auto()
    DOMAIN_REALM = auto()
    CAPATHS = auto()
    APPDEFAULTS = auto()
    PLUGINS = auto()


_SECTION_PARAMS = {
    KRB5ConfSection.LIBDEFAULTS: LIBDEFAULTS_PARAMS,
    KRB5ConfSection.APPDEFAULTS: APPDEFAULTS_PARAMS,
}


def validate_krb5_parameter(section: KRB5ConfSection, param: str, value: object) -> None:
    """Validate a krb5.conf parameter for the given section."""
    if isinstance(value, dict):
        for k, v in value.items():
            validate_krb5_parameter(section, k, v)
        return

    registry = _SECTION_PARAMS.get(section)
    if registry is None:
        raise ValueError(f'{section}: unexpected section type')

    descriptor = registry.get(param)
    if descriptor is None:
        raise ValueError(
            f'{param}: unsupported option for [{section.name.lower()}]')

    descriptor.validate(value)


def parse_krb_aux_params(
    section: KRB5ConfSection,
    section_conf: dict[str, object],
    aux_params: str
) -> None:
    """Parse auxiliary parameters and merge them into section_conf."""
    target = section_conf
    is_subsection = False

    for line in aux_params.splitlines():
        if not line.strip():
            continue

        entry = line.split('=')
        if len(entry) < 1:
            continue

        param = entry[0].strip()

        if entry[-1].strip() == KRB5_VALUE_BEGIN:
            if is_subsection:
                raise ValueError('Invalid nesting of parameters')
            sub: dict[str, object] = {}
            section_conf[param] = sub
            target = sub
            is_subsection = True
            continue

        elif param == KRB5_VALUE_END:
            target = section_conf
            is_subsection = False
            continue

        value = entry[1].strip()
        validate_krb5_parameter(section, param, value)
        target[param] = value


class KRB5Conf:
    """Builder for krb5.conf files."""

    def __init__(self) -> None:
        self.libdefaults: dict[str, object] = {}
        self.appdefaults: dict[str, object] = {}
        self.realms: dict[str, KRB5Realm] = {}

    def _add_parameters(
        self,
        section: KRB5ConfSection,
        config: dict[str, object],
        auxiliary_parameters: str | None = None
    ) -> None:
        for param, value in config.items():
            validate_krb5_parameter(section, param, value)

        data = deepcopy(config)

        if auxiliary_parameters:
            parse_krb_aux_params(section, data, auxiliary_parameters)

        match section:
            case KRB5ConfSection.APPDEFAULTS:
                self.appdefaults = data
            case KRB5ConfSection.LIBDEFAULTS:
                self.libdefaults = data
            case _:
                raise ValueError(f'{section}: unexpected section type')

    def add_libdefaults(
        self,
        config: dict[str, object],
        auxiliary_parameters: str | None = None
    ) -> None:
        """Add configuration for the [libdefaults] section."""
        self._add_parameters(KRB5ConfSection.LIBDEFAULTS, config, auxiliary_parameters)

    def add_appdefaults(
        self,
        config: dict[str, object],
        auxiliary_parameters: str | None = None
    ) -> None:
        """Add configuration for the [appdefaults] section."""
        self._add_parameters(KRB5ConfSection.APPDEFAULTS, config, auxiliary_parameters)

    def add_realms(self, realms: list[KRB5Realm]) -> None:
        """Add configuration for the [realms] section."""
        self.realms = {r.realm: r for r in realms}

    def _dump_parameter(self, parm: str, value: object) -> str | None:
        if value is None:
            return None

        if isinstance(value, dict):
            out = f'\t{parm} = {KRB5_VALUE_BEGIN}\n'
            for k, v in value.items():
                if (val := self._dump_parameter(k, v)) is None:
                    continue
                out += f'\t{val}'
            out += f'\t{KRB5_VALUE_END}\n'
            return out
        elif isinstance(value, list):
            if len(value) == 0:
                return None
            match parm:
                case 'kdc' | 'admin_server' | 'kpasswd_server':
                    return ''.join(f'\t{parm} = {srv}\n' for srv in value)
                case _:
                    return f'\t{parm} = {" ".join(value)}\n'
        else:
            return f'\t{parm} = {value}\n'

    def _generate_libdefaults(self) -> str:
        kconf = "[libdefaults]\n"
        for parm, value in self.libdefaults.items():
            kconf += self._dump_parameter(parm, value) or ''
        return kconf + '\n'

    def _generate_appdefaults(self) -> str:
        kconf = "[appdefaults]\n"
        for parm, value in self.appdefaults.items():
            kconf += self._dump_parameter(parm, value) or ''
        return kconf + '\n'

    def _generate_realms(self) -> str:
        kconf = '[realms]\n'
        for r in self.realms.values():
            realm_data: dict[str, object] = {'default_domain': r.realm}
            if r.primary_kdc is not None:
                realm_data['primary_kdc'] = format_server(r.primary_kdc)
            realm_data['admin_server'] = [format_server(s) for s in r.admin_server]
            realm_data['kdc'] = [format_server(s) for s in r.kdc]
            realm_data['kpasswd_server'] = [format_server(s) for s in r.kpasswd_server]
            kconf += self._dump_parameter(r.realm, realm_data) or ''
        return kconf + '\n'

    def _generate_domain_realms(self) -> str:
        kconf = '[domain_realms]\n'
        for realm in self.realms:
            kconf += f'\t{realm.lower()} = {realm}\n'
            kconf += f'\t.{realm.lower()} = {realm}\n'
            kconf += f'\t{realm.upper()} = {realm}\n'
            kconf += f'\t.{realm.upper()} = {realm}\n'
        return kconf + '\n'

    def generate(self) -> str:
        """Generate krb5.conf file content as a string."""
        kconf = self._generate_libdefaults()
        kconf += self._generate_appdefaults()
        kconf += self._generate_realms()
        kconf += self._generate_domain_realms()
        return kconf

    def write(self, path: str = '/etc/krb5.conf') -> None:
        """Write the krb5.conf file atomically to the specified path."""
        config = self.generate()
        with NamedTemporaryFile(delete=False, dir=os.path.dirname(path)) as f:
            f.write(config.encode())
            f.flush()
            os.fchmod(f.fileno(), 0o644)
            os.rename(f.name, path)
