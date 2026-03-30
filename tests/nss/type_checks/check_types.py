# SPDX-License-Identifier: LGPL-3.0-or-later
from typing import assert_type
import truenas_pynss

pw = truenas_pynss.getpwnam('root')
assert_type(pw, truenas_pynss.PasswdResult)
assert_type(pw.source, truenas_pynss.NssSource)
assert_type(pw.local, bool)
assert_type(pw.pw_uid, int)

pw_iter = truenas_pynss.iterpw()
assert_type(pw_iter, truenas_pynss.NssPasswdIter)

gr = truenas_pynss.getgrnam('root')
assert_type(gr, truenas_pynss.GroupResult)
assert_type(gr.gr_mem, tuple[str, ...])
assert_type(gr.source, truenas_pynss.NssSource)
assert_type(gr.local, bool)

gr_iter = truenas_pynss.itergrp()
assert_type(gr_iter, truenas_pynss.NssGroupIter)
