// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef TRUENAS_NSS_PWD_H
#define TRUENAS_NSS_PWD_H

#include <Python.h>

/*
 * Register PasswdResult PyStructSequence and NssPasswdIter type.
 * Returns 0 on success, -1 with exception on failure.
 */
int init_passwd_types(PyObject *module);

/* Python-callable module-level functions */
PyObject *py_getpwnam(PyObject *module, PyObject *args, PyObject *kwargs);
PyObject *py_getpwuid(PyObject *module, PyObject *args, PyObject *kwargs);
PyObject *py_iterpw(PyObject *module, PyObject *args, PyObject *kwargs);

#endif /* NSS_PWD_H */
