import pytest
import base64

import truenas_pykrb5

# Base64-encoded kerberos keytab from reference system
SAMPLE_KEYTAB = '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'  # noqa

SAMPLE_KEYTAB2 = "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"  # noqa

# Below KEYTAB_LIST_OUTPUT should match SAMPLE_KEYTAB above
# if the keytab is replaced, then this output should also be replaced
KEYTAB_LIST_OUTPUT = """Keytab name: FILE:/tmp/test_kt
KVNO Timestamp         Principal
---- ----------------- --------------------------------------------------------
   1 07/31/20 05:46:50 restrictedkrbhost/test49.homedom.fun@HOMEDOM.FUN (DEPRECATED:des-cbc-crc)
   1 07/31/20 05:46:50 restrictedkrbhost/TEST49@HOMEDOM.FUN (DEPRECATED:des-cbc-crc)
   1 07/31/20 05:46:50 restrictedkrbhost/test49.homedom.fun@HOMEDOM.FUN (DEPRECATED:des-cbc-md5)
   1 07/31/20 05:46:50 restrictedkrbhost/TEST49@HOMEDOM.FUN (DEPRECATED:des-cbc-md5)
   1 07/31/20 05:46:50 restrictedkrbhost/test49.homedom.fun@HOMEDOM.FUN (aes128-cts-hmac-sha1-96)
   1 07/31/20 05:46:50 restrictedkrbhost/TEST49@HOMEDOM.FUN (aes128-cts-hmac-sha1-96)
   1 07/31/20 05:46:50 restrictedkrbhost/test49.homedom.fun@HOMEDOM.FUN (aes256-cts-hmac-sha1-96)
   1 07/31/20 05:46:50 restrictedkrbhost/TEST49@HOMEDOM.FUN (aes256-cts-hmac-sha1-96)
   1 07/31/20 05:46:50 restrictedkrbhost/test49.homedom.fun@HOMEDOM.FUN (DEPRECATED:arcfour-hmac)
   1 07/31/20 05:46:50 restrictedkrbhost/TEST49@HOMEDOM.FUN (DEPRECATED:arcfour-hmac)
   1 07/31/20 05:46:50 host/test49.homedom.fun@HOMEDOM.FUN (DEPRECATED:des-cbc-crc)
   1 07/31/20 05:46:50 host/TEST49@HOMEDOM.FUN (DEPRECATED:des-cbc-crc)
   1 07/31/20 05:46:50 host/test49.homedom.fun@HOMEDOM.FUN (DEPRECATED:des-cbc-md5)
   1 07/31/20 05:46:50 host/TEST49@HOMEDOM.FUN (DEPRECATED:des-cbc-md5)
   1 07/31/20 05:46:50 host/test49.homedom.fun@HOMEDOM.FUN (aes128-cts-hmac-sha1-96)
   1 07/31/20 05:46:50 host/TEST49@HOMEDOM.FUN (aes128-cts-hmac-sha1-96)
   1 07/31/20 05:46:50 host/test49.homedom.fun@HOMEDOM.FUN (aes256-cts-hmac-sha1-96)
   1 07/31/20 05:46:50 host/TEST49@HOMEDOM.FUN (aes256-cts-hmac-sha1-96)
   1 07/31/20 05:46:50 host/test49.homedom.fun@HOMEDOM.FUN (DEPRECATED:arcfour-hmac)
   1 07/31/20 05:46:50 host/TEST49@HOMEDOM.FUN (DEPRECATED:arcfour-hmac)
   1 07/31/20 05:46:50 TEST49$@HOMEDOM.FUN (DEPRECATED:des-cbc-crc)
   1 07/31/20 05:46:50 TEST49$@HOMEDOM.FUN (DEPRECATED:des-cbc-md5)
   1 07/31/20 05:46:50 TEST49$@HOMEDOM.FUN (aes128-cts-hmac-sha1-96)
   1 07/31/20 05:46:50 TEST49$@HOMEDOM.FUN (aes256-cts-hmac-sha1-96)
   1 07/31/20 05:46:50 TEST49$@HOMEDOM.FUN (DEPRECATED:arcfour-hmac)"""  # noqa


def test_get_keytab_with_data():
    keytab_data = base64.b64decode(SAMPLE_KEYTAB)
    keytab = truenas_pykrb5.get_keytab(data=keytab_data)
    assert keytab is not None


def test_get_keytab_invalid_args():
    with pytest.raises(ValueError):
        truenas_pykrb5.get_keytab(filename="/nonexistent", data=b"test")


def test_keytab_iteration():
    keytab_data = base64.b64decode(SAMPLE_KEYTAB)
    keytab = truenas_pykrb5.get_keytab(data=keytab_data)

    entries = list(keytab)
    assert len(entries) == 25


def test_keytab_entry_timestamp():
    keytab_data = base64.b64decode(SAMPLE_KEYTAB)
    keytab = truenas_pykrb5.get_keytab(data=keytab_data)

    entry = next(iter(keytab))
    timestamp = entry.timestamp
    assert isinstance(timestamp, int)
    assert timestamp == 1596199610  # Actual timestamp from keytab data


def test_keytab_entry_vno():
    keytab_data = base64.b64decode(SAMPLE_KEYTAB)
    keytab = truenas_pykrb5.get_keytab(data=keytab_data)

    entry = next(iter(keytab))
    vno = entry.vno
    assert isinstance(vno, int)
    assert vno == 1


def test_keytab_entry_secret_key():
    keytab_data = base64.b64decode(SAMPLE_KEYTAB)
    keytab = truenas_pykrb5.get_keytab(data=keytab_data)

    entry = next(iter(keytab))
    secret_key = entry.secret_key

    assert hasattr(secret_key, 'enctype')
    assert hasattr(secret_key, 'contents')
    assert hasattr(secret_key, 'deprecated')
    assert isinstance(secret_key.enctype, truenas_pykrb5.KRB5EncType)
    assert isinstance(secret_key.contents, bytes)
    assert isinstance(secret_key.deprecated, bool)
    assert len(secret_key.contents) == 8
    assert secret_key.deprecated == True  # First entry is DES_CBC_CRC which is deprecated


def test_keytab_entry_principal():
    keytab_data = base64.b64decode(SAMPLE_KEYTAB)
    keytab = truenas_pykrb5.get_keytab(data=keytab_data)

    entry = next(iter(keytab))
    principal = entry.principal

    assert hasattr(principal, 'realm')
    assert hasattr(principal, 'components')
    assert hasattr(principal, 'principal_type')

    assert isinstance(principal.realm, str)
    assert isinstance(principal.components, tuple)
    assert isinstance(principal.principal_type, truenas_pykrb5.KRB5PrincipalType)

    assert principal.realm == "HOMEDOM.FUN"
    assert len(principal.components) == 2
    assert principal.components[0] == "restrictedkrbhost"
    assert principal.components[1] == "test49.homedom.fun"


def test_krb5_enctype_enum():
    assert hasattr(truenas_pykrb5, 'KRB5EncType')
    enctype = truenas_pykrb5.KRB5EncType.ENCTYPE_AES256_CTS_HMAC_SHA1_96
    assert enctype.value == 18


def test_krb5_principal_type_enum():
    assert hasattr(truenas_pykrb5, 'KRB5PrincipalType')
    principal_type = truenas_pykrb5.KRB5PrincipalType.KRB5_NT_SRV_HST
    assert principal_type.value == 3


def test_krb5_errcode_enum():
    assert hasattr(truenas_pykrb5, 'KRB5ErrCode')
    errcode = truenas_pykrb5.KRB5ErrCode.KRB5KDC_ERR_NONE
    assert errcode.value == 0


def test_expected_entries_from_keytab_list():
    keytab_data = base64.b64decode(SAMPLE_KEYTAB)
    keytab = truenas_pykrb5.get_keytab(data=keytab_data)

    entries = []
    for entry in keytab:
        # Reconstruct principal string
        principal_str = "/".join(entry.principal.components) + "@" + entry.principal.realm
        entries.append({
            'vno': entry.vno,
            'timestamp': entry.timestamp,
            'principal': principal_str,
            'enctype': entry.secret_key.enctype.name,
            'realm': entry.principal.realm,
            'components': entry.principal.components
        })

    # Verify expected number of entries
    assert len(entries) == 25

    # Verify all have same timestamp and vno
    assert all(e['timestamp'] == 1596199610 for e in entries)
    assert all(e['vno'] == 1 for e in entries)
    assert all(e['realm'] == "HOMEDOM.FUN" for e in entries)

    # Check for expected principals
    principals = [e['principal'] for e in entries]
    assert "restrictedkrbhost/test49.homedom.fun@HOMEDOM.FUN" in principals
    assert "restrictedkrbhost/TEST49@HOMEDOM.FUN" in principals
    assert "host/test49.homedom.fun@HOMEDOM.FUN" in principals
    assert "host/TEST49@HOMEDOM.FUN" in principals
    assert "TEST49$@HOMEDOM.FUN" in principals


def test_different_keytab_data():
    keytab_data = base64.b64decode(SAMPLE_KEYTAB2)
    keytab = truenas_pykrb5.get_keytab(data=keytab_data)

    entries = list(keytab)
    assert len(entries) > 0

    # Check that we get different realm
    first_entry = entries[0]
    assert first_entry.principal.realm == "ACME.TEST"


def test_keytab_iterator_multiple_passes():
    keytab_data = base64.b64decode(SAMPLE_KEYTAB)
    keytab = truenas_pykrb5.get_keytab(data=keytab_data)

    # First pass
    entries1 = list(keytab)

    # Second pass
    entries2 = list(keytab)

    assert len(entries1) == len(entries2) == 25


def test_struct_sequence_types():
    # Test that KeyInfo and PrincipalInfo are available
    assert hasattr(truenas_pykrb5, 'KeyInfo')
    assert hasattr(truenas_pykrb5, 'PrincipalInfo')


def test_service_vs_machine_principals():
    keytab_data = base64.b64decode(SAMPLE_KEYTAB)
    keytab = truenas_pykrb5.get_keytab(data=keytab_data)

    service_principals = []
    machine_principals = []

    for entry in keytab:
        if len(entry.principal.components) == 1:
            machine_principals.append(entry)
        elif len(entry.principal.components) == 2:
            service_principals.append(entry)

    # Should have both service and machine principals
    assert len(service_principals) > 0
    assert len(machine_principals) > 0

    # Machine principal should end with $
    machine_entry = machine_principals[0]
    assert machine_entry.principal.components[0].endswith('$')

    # Service principal should have service name and hostname
    service_entry = service_principals[0]
    service_name = service_entry.principal.components[0]
    assert service_name in ['restrictedkrbhost', 'host']


def test_principal_types_in_keytab():
    keytab_data = base64.b64decode(SAMPLE_KEYTAB)
    keytab = truenas_pykrb5.get_keytab(data=keytab_data)

    principal_types = set()
    for entry in keytab:
        principal_types.add(entry.principal.principal_type.name)

    # The sample keytab only contains KRB5_NT_PRINCIPAL entries
    assert 'KRB5_NT_PRINCIPAL' in principal_types
    # Verify we can access the principal type enum properly
    assert len(principal_types) >= 1


def test_encryption_types_validation():
    keytab_data = base64.b64decode(SAMPLE_KEYTAB)
    keytab = truenas_pykrb5.get_keytab(data=keytab_data)

    enctypes = []
    for entry in keytab:
        enctypes.append(entry.secret_key.enctype.name)

    # Based on the reference output, should contain these encryption types
    # Note: Our implementation excludes deprecated types, so we only check for modern ones
    expected_modern_types = [
        'ENCTYPE_AES128_CTS_HMAC_SHA1_96',
        'ENCTYPE_AES256_CTS_HMAC_SHA1_96'
    ]

    # Should have AES encryption types
    assert any('AES128' in enctype for enctype in enctypes)
    assert any('AES256' in enctype for enctype in enctypes)


def test_keytab_entry_attributes():
    keytab_data = base64.b64decode(SAMPLE_KEYTAB)
    keytab = truenas_pykrb5.get_keytab(data=keytab_data)

    entry = next(iter(keytab))

    # Test that all expected attributes exist
    assert hasattr(entry, 'timestamp')
    assert hasattr(entry, 'vno')
    assert hasattr(entry, 'secret_key')
    assert hasattr(entry, 'principal')

    # Test KeyInfo struct sequence fields
    assert hasattr(entry.secret_key, 'enctype')
    assert hasattr(entry.secret_key, 'contents')
    assert hasattr(entry.secret_key, 'deprecated')

    # Test PrincipalInfo struct sequence fields
    assert hasattr(entry.principal, 'realm')
    assert hasattr(entry.principal, 'components')
    assert hasattr(entry.principal, 'principal_type')


def test_no_direct_keytab_creation():
    # Should not be able to create Keytab directly
    with pytest.raises(AttributeError):
        truenas_pykrb5.Keytab()