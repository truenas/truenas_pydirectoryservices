// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef TRUENAS_NSS_GRP_H
#define TRUENAS_NSS_GRP_H

#include <Python.h>

/*
 * Register GroupResult PyStructSequence and NssGroupIter type.
 * Returns 0 on success, -1 with exception on failure.
 */
int init_group_types(PyObject *module);

/* Python-callable module-level functions */
PyObject *py_getgrnam(PyObject *module, PyObject *args, PyObject *kwargs);
PyObject *py_getgrgid(PyObject *module, PyObject *args, PyObject *kwargs);
PyObject *py_itergrp(PyObject *module, PyObject *args, PyObject *kwargs);

#endif /* NSS_GRP_H */
