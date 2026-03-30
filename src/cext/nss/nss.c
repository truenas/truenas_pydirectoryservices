// SPDX-License-Identifier: LGPL-3.0-or-later

#include <Python.h>
#include "common/includes.h"
#include "nss_state.h"
#include "nss_module.h"
#include "util_enum.h"
#include "nss_pwd.h"
#include "nss_grp.h"

#define MODULE_DOC \
	"CPython extension providing direct NSS lookups via dlopen'd NSS modules.\n\n" \
	"Supported modules: FILES (libnss_files), SSS (libnss_sss), " \
	"WINBIND (libnss_winbind).\n\n" \
	"Functions\n" \
	"---------\n" \
	"getpwnam(name, *, nss_module='ALL') -- look up passwd entry by name\n" \
	"getpwuid(uid, *, nss_module='ALL') -- look up passwd entry by uid\n" \
	"iterpw(*, nss_module='FILES') -- iterate passwd entries\n" \
	"getgrnam(name, *, nss_module='ALL') -- look up group entry by name\n" \
	"getgrgid(gid, *, nss_module='ALL') -- look up group entry by gid\n" \
	"itergrp(*, nss_module='FILES') -- iterate group entries\n"

/* ── NssReturnCode and NssModule enum tables ───────────────────────────── */

static const py_intenum_tbl_t nss_return_code_tbl[] = {
	{ "TRYAGAIN", NSS_STATUS_TRYAGAIN },
	{ "UNAVAIL", NSS_STATUS_UNAVAIL },
	{ "NOTFOUND", NSS_STATUS_NOTFOUND },
	{ "SUCCESS", NSS_STATUS_SUCCESS },
	{ "RETURN", NSS_STATUS_RETURN },
};

static const py_intenum_tbl_t nss_module_tbl[] = {
	{ "FILES", NSS_MOD_FILES },
	{ "SSS", NSS_MOD_SSS },
	{ "WINBIND", NSS_MOD_WINBIND },
	{ "ALL", NSS_MOD_ALL },
};

/* ── Method table ──────────────────────────────────────────────────────── */

PyDoc_STRVAR(py_getpwnam__doc__,
"getpwnam(name, *, nss_module='ALL')\n"
"--\n\n"
"Return the passwd database entry for the given user name.\n\n"
"Parameters\n"
"----------\n"
"name : str -- login name to look up\n"
"nss_module : str -- NSS module to query: 'FILES', 'SSS', 'WINBIND', or 'ALL'\n\n"
"Returns\n"
"-------\n"
"PasswdResult\n\n"
"Raises\n"
"------\n"
"KeyError -- name not found\n"
"NssError -- NSS lookup failed\n"
);

PyDoc_STRVAR(py_getpwuid__doc__,
"getpwuid(uid, *, nss_module='ALL')\n"
"--\n\n"
"Return the passwd database entry for the given user ID.\n\n"
"Parameters\n"
"----------\n"
"uid : int -- user ID to look up\n"
"nss_module : str -- NSS module to query\n\n"
"Returns\n"
"-------\n"
"PasswdResult\n\n"
"Raises\n"
"------\n"
"KeyError -- uid not found\n"
"NssError -- NSS lookup failed\n"
);

PyDoc_STRVAR(py_iterpw__doc__,
"iterpw(*, nss_module='FILES')\n"
"--\n\n"
"Return an iterator over passwd entries from a single NSS module.\n\n"
"Parameters\n"
"----------\n"
"nss_module : str -- NSS module to iterate: 'FILES', 'SSS', or 'WINBIND'\n\n"
"Returns\n"
"-------\n"
"iterator of PasswdResult\n\n"
"Notes\n"
"-----\n"
"Do not create two iterators for the same module concurrently in the same\n"
"thread; NSS modules store the iteration handle in a thread-local variable.\n"
);

PyDoc_STRVAR(py_getgrnam__doc__,
"getgrnam(name, *, nss_module='ALL')\n"
"--\n\n"
"Return the group database entry for the given group name.\n\n"
"Parameters\n"
"----------\n"
"name : str -- group name to look up\n"
"nss_module : str -- NSS module to query\n\n"
"Returns\n"
"-------\n"
"GroupResult\n\n"
"Raises\n"
"------\n"
"KeyError -- name not found\n"
"NssError -- NSS lookup failed\n"
);

PyDoc_STRVAR(py_getgrgid__doc__,
"getgrgid(gid, *, nss_module='ALL')\n"
"--\n\n"
"Return the group database entry for the given group ID.\n\n"
"Parameters\n"
"----------\n"
"gid : int -- group ID to look up\n"
"nss_module : str -- NSS module to query\n\n"
"Returns\n"
"-------\n"
"GroupResult\n\n"
"Raises\n"
"------\n"
"KeyError -- gid not found\n"
"NssError -- NSS lookup failed\n"
);

PyDoc_STRVAR(py_itergrp__doc__,
"itergrp(*, nss_module='FILES')\n"
"--\n\n"
"Return an iterator over group entries from a single NSS module.\n\n"
"Parameters\n"
"----------\n"
"nss_module : str -- NSS module to iterate: 'FILES', 'SSS', or 'WINBIND'\n\n"
"Returns\n"
"-------\n"
"iterator of GroupResult\n"
);

static PyMethodDef truenas_pynss_methods[] = {
	{
		.ml_name = "getpwnam",
		.ml_meth = (PyCFunction)py_getpwnam,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_getpwnam__doc__,
	},
	{
		.ml_name = "getpwuid",
		.ml_meth = (PyCFunction)py_getpwuid,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_getpwuid__doc__,
	},
	{
		.ml_name = "iterpw",
		.ml_meth = (PyCFunction)py_iterpw,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_iterpw__doc__,
	},
	{
		.ml_name = "getgrnam",
		.ml_meth = (PyCFunction)py_getgrnam,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_getgrnam__doc__,
	},
	{
		.ml_name = "getgrgid",
		.ml_meth = (PyCFunction)py_getgrgid,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_getgrgid__doc__,
	},
	{
		.ml_name = "itergrp",
		.ml_meth = (PyCFunction)py_itergrp,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_itergrp__doc__,
	},
	{ .ml_name = NULL },
};

/* ── Module definition ─────────────────────────────────────────────────── */

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "truenas_pynss",
	.m_doc = MODULE_DOC,
	.m_size = sizeof(truenas_pynss_state_t),
	.m_methods = truenas_pynss_methods,
};

/* Defined here so pwd.c / grp.c can call it via get_truenas_pynss_state(NULL) */
truenas_pynss_state_t *
get_truenas_pynss_state(PyObject *module)
{
	void *state;

	if (module == NULL) {
		module = PyState_FindModule(&moduledef);
		if (module == NULL)
			return NULL;
	}

	state = PyModule_GetState(module);
	return (truenas_pynss_state_t *)state;
}

int
nss_err_is_unavail(void)
{
	truenas_pynss_state_t *state = get_truenas_pynss_state(NULL);
	PyObject *exc_type, *exc_val, *exc_tb;
	PyObject *rc;
	long return_code;

	if (state == NULL || state->NssError == NULL)
		return 0;

	if (!PyErr_ExceptionMatches(state->NssError))
		return 0;

	PyErr_Fetch(&exc_type, &exc_val, &exc_tb);
	if (exc_val == NULL) {
		Py_XDECREF(exc_type);
		Py_XDECREF(exc_tb);
		return 0;
	}

	rc = PyObject_GetAttrString(exc_val, "return_code");
	if (rc == NULL) {
		PyErr_Clear();
		PyErr_Restore(exc_type, exc_val, exc_tb);
		return 0;
	}

	return_code = PyLong_AsLong(rc);
	Py_DECREF(rc);

	if (return_code == NSS_STATUS_UNAVAIL) {
		Py_XDECREF(exc_type);
		Py_XDECREF(exc_val);
		Py_XDECREF(exc_tb);
		return 1;
	}

	PyErr_Restore(exc_type, exc_val, exc_tb);
	return 0;
}

/*
 * Build the NssSource StrEnum and cache its members in module state.
 * Returns 0 on success, -1 with exception on failure.
 */
static int
init_nss_source_enum(PyObject *m, PyObject *StrEnum, truenas_pynss_state_t *state)
{
	PyObject *src_name = PyUnicode_FromString("NssSource");
	PyObject *src_dict = PyDict_New();
	PyObject *src_args = NULL;

	if (src_name == NULL || src_dict == NULL) {
		Py_XDECREF(src_name);
		Py_XDECREF(src_dict);
		return -1;
	}

	PyObject *fs = PyUnicode_FromString("FILES");
	PyObject *ss = PyUnicode_FromString("SSS");
	PyObject *wb = PyUnicode_FromString("WINBIND");
	if (fs == NULL || ss == NULL || wb == NULL ||
	    PyDict_SetItemString(src_dict, "FILES", fs) < 0 ||
	    PyDict_SetItemString(src_dict, "SSS", ss) < 0 ||
	    PyDict_SetItemString(src_dict, "WINBIND", wb) < 0) {
		Py_XDECREF(fs); Py_XDECREF(ss); Py_XDECREF(wb);
		Py_DECREF(src_dict);
		Py_DECREF(src_name);
		return -1;
	}
	Py_DECREF(fs); Py_DECREF(ss); Py_DECREF(wb);

	src_args = PyTuple_Pack(2, src_name, src_dict);
	Py_DECREF(src_name);
	Py_DECREF(src_dict);
	if (src_args == NULL)
		return -1;

	state->NssSourceEnum = PyObject_Call(StrEnum, src_args, NULL);
	Py_DECREF(src_args);
	if (state->NssSourceEnum == NULL)
		return -1;

	if (PyModule_AddObjectRef(m, "NssSource", state->NssSourceEnum) < 0)
		return -1;

	state->NssSourceMembers[NSS_MOD_FILES] =
		PyObject_GetAttrString(state->NssSourceEnum, "FILES");
	state->NssSourceMembers[NSS_MOD_SSS] =
		PyObject_GetAttrString(state->NssSourceEnum, "SSS");
	state->NssSourceMembers[NSS_MOD_WINBIND] =
		PyObject_GetAttrString(state->NssSourceEnum, "WINBIND");

	if (state->NssSourceMembers[NSS_MOD_FILES] == NULL ||
	    state->NssSourceMembers[NSS_MOD_SSS] == NULL ||
	    state->NssSourceMembers[NSS_MOD_WINBIND] == NULL)
		return -1;

	return 0;
}

/* ── Module initializer ────────────────────────────────────────────────── */

static PyObject *
module_init(void)
{
	PyObject *m = NULL;
	PyObject *enum_mod = NULL;
	PyObject *IntEnum = NULL;
	PyObject *StrEnum = NULL;
	truenas_pynss_state_t *state;

	m = PyModule_Create(&moduledef);
	if (m == NULL)
		return NULL;

	/* 1. Register PasswdResult + NssPasswdIter */
	if (init_passwd_types(m) < 0)
		goto error;

	/* 2. Register GroupResult + NssGroupIter */
	if (init_group_types(m) < 0)
		goto error;

	/* 3. Build NssReturnCode and NssModule IntEnums */
	enum_mod = PyImport_ImportModule("enum");
	if (enum_mod == NULL)
		goto error;

	IntEnum = PyObject_GetAttrString(enum_mod, "IntEnum");
	StrEnum = PyObject_GetAttrString(enum_mod, "StrEnum");
	Py_DECREF(enum_mod);
	enum_mod = NULL;
	if (IntEnum == NULL || StrEnum == NULL)
		goto error;

	state = get_truenas_pynss_state(m);
	if (state == NULL)
		goto error;

	if (add_enum(m, IntEnum, "NssReturnCode",
	             nss_return_code_tbl,
	             TABLE_SIZE(nss_return_code_tbl),
	             NULL,
	             &state->NssReturnCodeEnum) < 0)
		goto error;

	if (add_enum(m, IntEnum, "NssModule",
	             nss_module_tbl,
	             TABLE_SIZE(nss_module_tbl),
	             NULL,
	             &state->NssModuleEnum) < 0)
		goto error;

	Py_DECREF(IntEnum);
	IntEnum = NULL;

	/* 3b. Build NssSource StrEnum */
	if (init_nss_source_enum(m, StrEnum, state) < 0)
		goto error;

	Py_DECREF(StrEnum);
	StrEnum = NULL;

	/* 4. Create NssError exception */
	state->NssError = PyErr_NewException("truenas_pynss.NssError", NULL, NULL);
	if (state->NssError == NULL)
		goto error;

	if (PyModule_AddObjectRef(m, "NssError", state->NssError) < 0)
		goto error;

	return m;

error:
	Py_XDECREF(StrEnum);
	Py_XDECREF(IntEnum);
	Py_XDECREF(enum_mod);
	Py_DECREF(m);
	return NULL;
}

PyMODINIT_FUNC
PyInit_truenas_pynss(void)
{
	return module_init();
}
