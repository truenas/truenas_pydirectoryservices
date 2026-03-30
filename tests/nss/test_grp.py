# SPDX-License-Identifier: LGPL-3.0-or-later
import pytest
import truenas_pynss


def test_getgrnam_root():
    gr = truenas_pynss.getgrnam('root')
    assert isinstance(gr, truenas_pynss.GroupResult)
    assert gr.gr_gid == 0
    assert gr.source == truenas_pynss.NssSource.FILES


def test_getgrgid_root():
    gr = truenas_pynss.getgrgid(0)
    assert isinstance(gr, truenas_pynss.GroupResult)
    assert gr.gr_name == 'root'
    assert gr.source == truenas_pynss.NssSource.FILES


def test_getgrnam_nonexistent():
    with pytest.raises(KeyError):
        truenas_pynss.getgrnam('__nonexistent__')


def test_itergrp_yields_group_results():
    entries = list(truenas_pynss.itergrp())
    assert len(entries) >= 1
    assert all(isinstance(e, truenas_pynss.GroupResult) for e in entries)


def test_itergrp_all_raises():
    with pytest.raises((ValueError, TypeError)):
        truenas_pynss.itergrp(nss_module='ALL')


def test_gr_mem_is_tuple():
    gr = truenas_pynss.getgrnam('root')
    assert isinstance(gr.gr_mem, tuple)


def test_nss_module_is_keyword_only():
    with pytest.raises(TypeError):
        truenas_pynss.getgrnam('root', 'FILES')
    with pytest.raises(TypeError):
        truenas_pynss.getgrgid(0, 'FILES')
    with pytest.raises(TypeError):
        truenas_pynss.itergrp('FILES')


def test_itergrp_context_manager():
    entries = []
    with truenas_pynss.itergrp() as it:
        for gr in it:
            entries.append(gr)
    assert len(entries) >= 1


def test_itergrp_context_manager_early_exit():
    with truenas_pynss.itergrp() as it:
        first = next(it)
        assert isinstance(first, truenas_pynss.GroupResult)
    assert list(it) == []
