# SPDX-License-Identifier: LGPL-3.0-or-later
import pytest
import truenas_pynss


def test_getpwnam_root():
    pw = truenas_pynss.getpwnam('root')
    assert isinstance(pw, truenas_pynss.PasswdResult)
    assert pw.pw_uid == 0
    assert pw.source == truenas_pynss.NssSource.FILES


def test_getpwuid_root():
    pw = truenas_pynss.getpwuid(0)
    assert isinstance(pw, truenas_pynss.PasswdResult)
    assert pw.pw_name == 'root'
    assert pw.source == truenas_pynss.NssSource.FILES


def test_getpwnam_explicit_module():
    pw = truenas_pynss.getpwnam('root', nss_module='FILES')
    assert pw.pw_uid == 0
    assert pw.source == truenas_pynss.NssSource.FILES


def test_getpwnam_nonexistent():
    with pytest.raises(KeyError):
        truenas_pynss.getpwnam('__nonexistent__')


def test_iterpw_yields_passwd_results():
    entries = list(truenas_pynss.iterpw())
    assert len(entries) >= 1
    assert all(isinstance(e, truenas_pynss.PasswdResult) for e in entries)
    assert any(e.pw_name == 'root' for e in entries)


def test_iterpw_all_raises():
    with pytest.raises((ValueError, TypeError)):
        truenas_pynss.iterpw(nss_module='ALL')


def test_source_is_nss_source():
    pw = truenas_pynss.getpwnam('root')
    assert isinstance(pw.source, truenas_pynss.NssSource)
    assert not type(pw.source) is str


def test_nss_module_is_keyword_only():
    with pytest.raises(TypeError):
        truenas_pynss.getpwnam('root', 'FILES')
    with pytest.raises(TypeError):
        truenas_pynss.getpwuid(0, 'FILES')
    with pytest.raises(TypeError):
        truenas_pynss.iterpw('FILES')


def test_iterpw_context_manager():
    entries = []
    with truenas_pynss.iterpw() as it:
        for pw in it:
            entries.append(pw)
    assert len(entries) >= 1
    assert any(e.pw_name == 'root' for e in entries)


def test_iterpw_context_manager_early_exit():
    with truenas_pynss.iterpw() as it:
        first = next(it)
        assert isinstance(first, truenas_pynss.PasswdResult)
    # Iterator should be closed after exiting context
    assert list(it) == []
