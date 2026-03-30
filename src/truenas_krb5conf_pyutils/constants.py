# SPDX-License-Identifier: LGPL-3.0-or-later

from dataclasses import dataclass
from enum import Enum, auto
from types import MappingProxyType

from truenas_pykrb5 import KRB5EncType


class KRB5ParamType(Enum):
    BOOLEAN = auto()
    STRING = auto()
    TIME = auto()
    ETYPES = auto()
    REALM = auto()
    CCNAME = auto()
    NUMBER = auto()
    ADDRESS = auto()


def enctype_to_conf_string(enctype: KRB5EncType) -> str:
    """Convert a KRB5EncType member to its krb5.conf string form.

    ENCTYPE_AES256_CTS_HMAC_SHA1_96 -> 'aes256-cts-hmac-sha1-96'
    """
    return enctype.name.removeprefix('ENCTYPE_').lower().replace('_', '-')


_ENCTYPE_ALIASES = frozenset({'aes', 'camellia', 'arcfour-hmac-md5'})

SUPPORTED_ETYPES: frozenset[str] = frozenset(
    enctype_to_conf_string(e) for e in KRB5EncType
    if e not in (KRB5EncType.ENCTYPE_NULL, KRB5EncType.ENCTYPE_UNKNOWN)
) | _ENCTYPE_ALIASES


@dataclass(frozen=True, slots=True)
class KRB5Param:
    conf_name: str
    param_type: KRB5ParamType

    def validate(self, value: object) -> None:
        match self.param_type:
            case KRB5ParamType.BOOLEAN:
                if value not in ('true', 'false'):
                    raise ValueError(
                        f'{value!r}: not a boolean for {self.conf_name}')
            case (KRB5ParamType.STRING | KRB5ParamType.REALM |
                  KRB5ParamType.CCNAME | KRB5ParamType.ADDRESS):
                if not isinstance(value, str):
                    raise ValueError(
                        f'{value!r}: not a string for {self.conf_name}')
            case KRB5ParamType.ETYPES:
                if not isinstance(value, str):
                    raise ValueError(
                        f'{value!r}: not a string for {self.conf_name}')
                if ',' in value:
                    raise ValueError('enctypes should be space-delimited')
                for et in value.split():
                    if et.strip() not in SUPPORTED_ETYPES:
                        raise ValueError(
                            f'{et}: unsupported enctype for {self.conf_name}')
            case KRB5ParamType.TIME | KRB5ParamType.NUMBER:
                if isinstance(value, int):
                    pass
                elif isinstance(value, str) and value.isdigit():
                    pass
                else:
                    raise ValueError(
                        f'{value!r}: must be integer or digit string '
                        f'for {self.conf_name}')


LIBDEFAULTS_PARAMS: MappingProxyType[str, KRB5Param] = MappingProxyType({
    p.conf_name: p for p in [
        KRB5Param('default_realm', KRB5ParamType.REALM),
        KRB5Param('canonicalize', KRB5ParamType.BOOLEAN),
        KRB5Param('clockskew', KRB5ParamType.TIME),
        KRB5Param('default_ccache_name', KRB5ParamType.CCNAME),
        KRB5Param('default_tgs_enctypes', KRB5ParamType.ETYPES),
        KRB5Param('default_tkt_enctypes', KRB5ParamType.ETYPES),
        KRB5Param('dns_canonicalize_hostname', KRB5ParamType.STRING),
        KRB5Param('dns_lookup_kdc', KRB5ParamType.BOOLEAN),
        KRB5Param('dns_lookup_realm', KRB5ParamType.BOOLEAN),
        KRB5Param('dns_uri_lookup', KRB5ParamType.BOOLEAN),
        KRB5Param('kdc_timesync', KRB5ParamType.BOOLEAN),
        KRB5Param('max_retries', KRB5ParamType.NUMBER),
        KRB5Param('ticket_lifetime', KRB5ParamType.TIME),
        KRB5Param('renew_lifetime', KRB5ParamType.TIME),
        KRB5Param('forwardable', KRB5ParamType.BOOLEAN),
        KRB5Param('qualify_shortname', KRB5ParamType.STRING),
        KRB5Param('proxiable', KRB5ParamType.BOOLEAN),
        KRB5Param('verify_ap_req_nofail', KRB5ParamType.BOOLEAN),
        KRB5Param('permitted_enctypes', KRB5ParamType.ETYPES),
        KRB5Param('noaddresses', KRB5ParamType.BOOLEAN),
        KRB5Param('extra_addresses', KRB5ParamType.ADDRESS),
        KRB5Param('rdns', KRB5ParamType.BOOLEAN),
        KRB5Param('udp_preference_limit', KRB5ParamType.NUMBER),
    ]
})

APPDEFAULTS_PARAMS: MappingProxyType[str, KRB5Param] = MappingProxyType({
    p.conf_name: p for p in [
        KRB5Param('forwardable', KRB5ParamType.BOOLEAN),
        KRB5Param('proxiable', KRB5ParamType.BOOLEAN),
        KRB5Param('no-addresses', KRB5ParamType.BOOLEAN),
        KRB5Param('ticket_lifetime', KRB5ParamType.TIME),
        KRB5Param('renew_lifetime', KRB5ParamType.TIME),
        KRB5Param('encrypt', KRB5ParamType.BOOLEAN),
        KRB5Param('forward', KRB5ParamType.BOOLEAN),
    ]
})


@dataclass(frozen=True, slots=True)
class KRB5Realm:
    realm: str
    kdc: list[str]
    admin_server: list[str]
    kpasswd_server: list[str]
    primary_kdc: str | None = None
