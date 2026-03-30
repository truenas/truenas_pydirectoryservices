# SPDX-License-Identifier: LGPL-3.0-or-later
#
# Tests for truenas_krb5conf_pyutils
# Adapted from middleware tests/unit/test_krb5.py

import os
import pytest

from truenas_krb5conf_pyutils import (
    KRB5Conf,
    KRB5ConfSection,
    KRB5Realm,
    format_server,
    parse_krb_aux_params,
)


APPDEFAULTS_AUX = """
pam = {
    renew_lifetime = 86400
}
"""

REALMS = [
    KRB5Realm(
        realm='AD02.TN.IXSYSTEMS.NET',
        primary_kdc='10.238.238.2',
        kdc=['10.238.238.2', '10.238.238.3'],
        admin_server=['10.238.238.2'],
        kpasswd_server=['10.238.238.2'],
    ),
    KRB5Realm(
        realm='AD03.TN.IXSYSTEMS.NET',
        primary_kdc=None,
        kdc=[],
        admin_server=[],
        kpasswd_server=[],
    ),
]


@pytest.mark.parametrize('params,expected,success', [
    ('dns_canonicalize_hostname = true', {'dns_canonicalize_hostname': 'true'}, True),
    ('canonicalize = true', {'canonicalize': 'true'}, True),
    ('admin_server = canary', None, False),  # invalid entry
    ('rdns = canary', None, False),  # wrong type for boolean value
    ('permitted_enctypes = aes256-cts-hmac-sha1-96', {'permitted_enctypes': 'aes256-cts-hmac-sha1-96'}, True),
    ('permitted_enctypes = canary', None, False),  # not a valid encryption type
])
def test__krb5conf_libdefaults_aux_parser(params, expected, success):
    data = {}

    if success:
        parse_krb_aux_params(
            KRB5ConfSection.LIBDEFAULTS,
            data,
            params
        )
        assert data == expected

    else:
        with pytest.raises(ValueError):
            parse_krb_aux_params(
                KRB5ConfSection.LIBDEFAULTS,
                data,
                params
            )


@pytest.mark.parametrize('params,expected,success', [
    ('renew_lifetime = 86400', {'renew_lifetime': '86400'}, True),
    ('canonicalize = true', None, False),
    (APPDEFAULTS_AUX, {'pam': {'renew_lifetime': '86400'}}, True),
])
def test__krb5conf_appdefaults_aux_parser(params, expected, success):
    data = {}

    if success:
        parse_krb_aux_params(
            KRB5ConfSection.APPDEFAULTS,
            data,
            params
        )
        assert data == expected

    else:
        with pytest.raises(ValueError):
            parse_krb_aux_params(
                KRB5ConfSection.APPDEFAULTS,
                data,
                params
            )


def validate_realms_section(data):
    """
    data will consist of approximately following:

    \tAD02.TN.IXSYSTEMS.NET = {\n
    \t\tdefault_domain = AD02.TN.IXSYSTEMS.NET\n
    \t\tkdc = ip1 ip2 ip3\n
    \t\tadmin_server = ip1\n
    \t\tkpasswd_server = ip1 ip2 ip3\n
    """
    def validate_realm(idx, realm):
        this = REALMS[idx]
        lidx = 0
        for line in realm.splitlines():
            if not line.strip():
                continue

            match lidx:
                case 0:
                    assert line.startswith(f'\t{this.realm} =')
                case 1:
                    assert line.strip() == f'default_domain = {this.realm}', str(realm)
                case _:
                    data = line.split('=')
                    assert len(data) == 2, realm
                    key, val = data
                    key = key.strip()

                    match key:
                        case 'kdc':
                            assert val.strip() in this.kdc
                        case 'admin_server':
                            assert val.strip() in this.admin_server
                        case 'kpasswd_server':
                            assert val.strip() in this.kpasswd_server
                        case 'primary_kdc':
                            assert val.strip() == this.primary_kdc
                        case _:
                            raise ValueError(f'{key}: unexpected key in realm config')

            lidx += 1

    for idx, realm in enumerate(data.split('}')):
        if not realm.strip():
            continue

        validate_realm(idx, realm)


def validate_domain_realms_section(data):
    """
    data will consist of approximately following:

    \tad02.tn.ixsystems.net = AD02.TN.IXSYSTEMS.NET\n
    \t.ad02.tn.ixsystems.net = AD02.TN.IXSYSTEMS.NET\n
    \tAD02.TN.IXSYSTEMS.NET = AD02.TN.IXSYSTEMS.NET\n
    \t.AD02.TN.IXSYSTEMS.NET = AD02.TN.IXSYSTEMS.NET\n
    """
    realm_idx = 0

    for idx, line in enumerate(data.splitlines()):
        relative_idx = idx % 4
        if idx and relative_idx == 0:
            realm_idx += 1

        realm_name = REALMS[realm_idx].realm

        match relative_idx:
            case 0:
                assert line.strip() == f'{realm_name.lower()} = {realm_name}'
            case 1:
                assert line.strip() == f'.{realm_name.lower()} = {realm_name}'
            case 2:
                assert line.strip() == f'{realm_name.upper()} = {realm_name}'
            case 3:
                assert line.strip() == f'.{realm_name.upper()} = {realm_name}'


def test__krb5conf_realm():
    """
    Verify that a list of kerberos realms is stored properly
    within a KRB5Conf object
    """
    kconf = KRB5Conf()

    kconf.add_realms(REALMS)

    stored_realms = kconf.realms
    for realm in REALMS:
        assert realm.realm in stored_realms

        stored = stored_realms[realm.realm]
        assert stored.realm == realm.realm
        assert stored.admin_server == realm.admin_server
        assert stored.kpasswd_server == realm.kpasswd_server
        assert stored.kdc == realm.kdc

    # Convert our stored kerberos realm configuration into krb5.conf
    # data via `generate()` method and validate it's what we expect.
    for section in kconf.generate().split('\n\n'):
        if not section.startswith(('[realms]', '[domain_realms]')):
            continue

        section_name, data = section.split('\n', 1)
        match section_name:
            case '[realms]':
                validate_realms_section(data)
            case '[domain_realms]':
                validate_domain_realms_section(data)
            case _:
                raise ValueError(f'{section_name}: unexpected entry')


def test__krb5conf_libdefaults():
    """
    Validate generating krb5.conf with libdefault configured via
    config dict and auxiliary parameter blob
    """
    kconf = KRB5Conf()
    kconf.add_libdefaults(
        {'canonicalize': 'true'},
        'rdns = false\npermitted_enctypes = aes256-cts-hmac-sha1-96'
    )

    for section in kconf.generate().split('\n\n'):
        if not section.startswith('[libdefaults]'):
            continue

        section_name, data = section.split('\n', 1)

        for line in data.splitlines():
            if not line.strip():
                continue

            key, value = line.strip().split('=')

            match key.strip():
                case 'canonicalize':
                    assert value.strip() == 'true'
                case 'rdns':
                    assert value.strip() == 'false'
                case 'permitted_enctypes':
                    assert value.strip() == 'aes256-cts-hmac-sha1-96'
                case _:
                    raise ValueError(f'{key}: unexpected libdefault parameter')


def test__krb5conf_appdefaults():
    """
    Validate generating krb5.conf with libdefault configured via
    config dict and auxiliary parameter blob
    """
    kconf = KRB5Conf()
    kconf.add_appdefaults(
        {'renew_lifetime': '86400'},
        'forwardable = true\nproxiable = false'
    )

    for section in kconf.generate().split('\n\n'):
        if not section.startswith('[appdefaults]'):
            continue

        section_name, data = section.split('\n', 1)

        for line in data.splitlines():
            if not line.strip():
                continue

            key, value = line.strip().split('=')

            match key.strip():
                case 'renew_lifetime':
                    assert value.strip() == '86400'
                case 'forwardable':
                    assert value.strip() == 'true'
                case 'proxiable':
                    assert value.strip() == 'false'
                case _:
                    raise ValueError(f'{key}: unexpected libdefault parameter')


def test__write_krb5_conf(tmpdir):
    kconf = KRB5Conf()
    kconf.add_realms(REALMS)
    kconf.add_libdefaults({'default_realm': 'AD02.TN.IXSYSTEMS.NET'})

    data = kconf.generate()

    path = os.path.join(tmpdir, 'test_krb5.conf')
    kconf.write(path)

    with open(path, 'r') as f:
        assert f.read() == data


@pytest.mark.parametrize('address,expected', [
    ('10.238.238.2', '10.238.238.2'),  # IPv4 unchanged
    ('192.168.1.1', '192.168.1.1'),  # IPv4 unchanged
    ('kdc.example.com', 'kdc.example.com'),  # hostname unchanged
    ('2001:db8::1', '[2001:db8::1]'),  # IPv6 wrapped
    ('fe80::1', '[fe80::1]'),  # IPv6 wrapped
    (' 2001:db8::1 ', '[2001:db8::1]'),  # IPv6 with whitespace
    (' 10.1.1.1 ', '10.1.1.1'),  # IPv4 with whitespace
    ('[2001:db8::1]', '[2001:db8::1]'),  # IPv6 already bracketed
    ('[fe80::1]', '[fe80::1]'),  # IPv6 already bracketed
    (' [2001:db8::1] ', '[2001:db8::1]'),  # IPv6 already bracketed with whitespace
])
def test__format_server(address, expected):
    """
    Test that format_server properly wraps IPv6 addresses in brackets
    and leaves IPv4 addresses and hostnames unchanged
    """
    assert format_server(address) == expected


def test__krb5conf_ipv6_in_realm():
    """
    Test that IPv6 addresses in realm configuration are properly
    wrapped in brackets in the generated krb5.conf file
    """
    realms = [KRB5Realm(
        realm='IPV6TEST.NET',
        primary_kdc='2001:db8::1',
        kdc=['2001:db8::1', '2001:db8::2', 'fe80::1'],
        admin_server=['2001:db8::1'],
        kpasswd_server=['2001:db8::2'],
    )]

    kconf = KRB5Conf()
    kconf.add_realms(realms)

    config = kconf.generate()

    # Find the [realms] section
    realms_section = None
    for section in config.split('\n\n'):
        if section.startswith('[realms]'):
            realms_section = section
            break

    assert realms_section is not None, "No [realms] section found in generated config"

    # Verify that IPv6 addresses are wrapped in brackets
    assert 'primary_kdc = [2001:db8::1]' in realms_section
    assert 'kdc = [2001:db8::1]' in realms_section
    assert 'kdc = [2001:db8::2]' in realms_section
    assert 'kdc = [fe80::1]' in realms_section
    assert 'admin_server = [2001:db8::1]' in realms_section
    assert 'kpasswd_server = [2001:db8::2]' in realms_section

    # Verify that unwrapped IPv6 addresses are NOT present
    assert 'primary_kdc = 2001:db8::1' not in realms_section
    assert 'kdc = 2001:db8::1\n' not in realms_section


def test__krb5conf_mixed_ipv4_ipv6_in_realm():
    """
    Test that mixed IPv4/IPv6 addresses and hostnames in realm configuration
    are properly formatted in the generated krb5.conf file
    """
    realms = [KRB5Realm(
        realm='MIXED.NET',
        primary_kdc='kdc.mixed.net',
        kdc=[
            '10.1.1.1',  # IPv4
            '2001:db8::1',  # IPv6
            'kdc2.mixed.net',  # hostname
            'fe80::1',  # IPv6
        ],
        admin_server=['192.168.1.1', '2001:db8::2'],
        kpasswd_server=['kdc.mixed.net'],
    )]

    kconf = KRB5Conf()
    kconf.add_realms(realms)

    config = kconf.generate()

    # Find the [realms] section
    realms_section = None
    for section in config.split('\n\n'):
        if section.startswith('[realms]'):
            realms_section = section
            break

    assert realms_section is not None

    # Verify IPv4 addresses are NOT wrapped
    assert 'kdc = 10.1.1.1' in realms_section
    assert 'admin_server = 192.168.1.1' in realms_section
    assert 'kdc = [10.1.1.1]' not in realms_section

    # Verify IPv6 addresses ARE wrapped
    assert 'kdc = [2001:db8::1]' in realms_section
    assert 'kdc = [fe80::1]' in realms_section
    assert 'admin_server = [2001:db8::2]' in realms_section

    # Verify hostnames are NOT wrapped
    assert 'primary_kdc = kdc.mixed.net' in realms_section
    assert 'kdc = kdc2.mixed.net' in realms_section
    assert 'kpasswd_server = kdc.mixed.net' in realms_section


def test__krb5conf_ipv6_with_whitespace():
    """
    Test that IPv6 addresses with leading/trailing whitespace
    are properly stripped and wrapped in brackets
    """
    realms = [KRB5Realm(
        realm='WHITESPACE.NET',
        primary_kdc=' 2001:db8::1 ',
        kdc=[' fe80::1 ', '  2001:db8::100  '],
        admin_server=[' 2001:db8::2'],
        kpasswd_server=['2001:db8::3 '],
    )]

    kconf = KRB5Conf()
    kconf.add_realms(realms)

    config = kconf.generate()

    # Find the [realms] section
    realms_section = None
    for section in config.split('\n\n'):
        if section.startswith('[realms]'):
            realms_section = section
            break

    assert realms_section is not None

    # Verify IPv6 addresses are properly formatted (no extra whitespace, wrapped in brackets)
    assert 'primary_kdc = [2001:db8::1]' in realms_section
    assert 'kdc = [fe80::1]' in realms_section
    assert 'kdc = [2001:db8::100]' in realms_section
    assert 'admin_server = [2001:db8::2]' in realms_section
    assert 'kpasswd_server = [2001:db8::3]' in realms_section


def test__krb5conf_ipv6_already_bracketed():
    """
    Test that IPv6 addresses that are already wrapped in brackets
    are not double-wrapped in the generated krb5.conf file
    """
    realms = [KRB5Realm(
        realm='BRACKETED.NET',
        primary_kdc='[2001:db8::1]',
        kdc=['[2001:db8::1]', '[fe80::1]', '10.1.1.1'],
        admin_server=['[2001:db8::2]'],
        kpasswd_server=['[2001:db8::3]'],
    )]

    kconf = KRB5Conf()
    kconf.add_realms(realms)

    config = kconf.generate()

    # Find the [realms] section
    realms_section = None
    for section in config.split('\n\n'):
        if section.startswith('[realms]'):
            realms_section = section
            break

    assert realms_section is not None

    # Verify IPv6 addresses are not double-wrapped
    assert 'primary_kdc = [2001:db8::1]' in realms_section
    assert 'kdc = [2001:db8::1]' in realms_section
    assert 'kdc = [fe80::1]' in realms_section
    assert 'admin_server = [2001:db8::2]' in realms_section
    assert 'kpasswd_server = [2001:db8::3]' in realms_section

    # Verify no double-wrapping occurred
    assert '[[2001:db8::1]]' not in realms_section
    assert '[[fe80::1]]' not in realms_section
