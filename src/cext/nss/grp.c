// SPDX-License-Identifier: LGPL-3.0-or-later

#include <Python.h>
#include "common/includes.h"
#include "nss_state.h"
#include "nss_module.h"
#include "nss_grp.h"

#define GROUP_INIT_BUFLEN 1024

/* ── GroupResult PyStructSequence ──────────────────────────────────────── */

enum {
	GR_NAME,
	GR_GID,
	GR_MEM,
	GR_SOURCE,
	GR_LOCAL,
	GR_FIELD_COUNT
};

static PyStructSequence_Field group_result_fields[] = {
	{ "gr_name", "Group name" },
	{ "gr_gid", "Group ID" },
	{ "gr_mem", "Tuple of group member login names" },
	{ "source", "NSS module that provided this entry (e.g. 'FILES')" },
	{ "local", "True if the entry was provided by the FILES module" },
	{ NULL }
};

static PyStructSequence_Desc group_result_desc = {
	.name = "truenas_pynss.GroupResult",
	.doc = "Group database entry returned by NSS lookup",
	.fields = group_result_fields,
	.n_in_sequence = GR_FIELD_COUNT,
};

/* ── NssError helper ───────────────────────────────────────────────────── */

static void
raise_nss_error(int nss_errno, const char *nssop,
                enum nss_status return_code, int mod_idx)
{
	truenas_pynss_state_t *state = get_truenas_pynss_state(NULL);
	PyObject *exc_type;
	PyObject *exc = NULL;
	PyObject *v;

	if (state == NULL || state->NssError == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "NssError type not initialized");
		return;
	}

	exc_type = state->NssError;
	exc = PyObject_CallNoArgs(exc_type);
	if (exc == NULL)
		return;

	v = PyLong_FromLong(nss_errno);
	if (v) {
		PyObject_SetAttrString(exc, "errno", v);
		Py_DECREF(v);
	}

	v = PyUnicode_FromString(nssop);
	if (v) {
		PyObject_SetAttrString(exc, "nssop", v);
		Py_DECREF(v);
	}

	v = PyLong_FromLong((long)return_code);
	if (v) {
		PyObject_SetAttrString(exc, "return_code", v);
		Py_DECREF(v);
	}

	v = PyUnicode_FromString(mod_idx_to_name(mod_idx));
	if (v) {
		PyObject_SetAttrString(exc, "module", v);
		Py_DECREF(v);
	}

	PyErr_SetObject(exc_type, exc);
	Py_DECREF(exc);
}

/* ── C-level group result builder ─────────────────────────────────────── */

static PyObject *
build_group_result(const struct group *gr, int mod_idx)
{
	truenas_pynss_state_t *state = get_truenas_pynss_state(NULL);
	PyObject *result;
	PyObject *members;
	int i;

	if (state == NULL || state->GroupResultType == NULL) {
		PyErr_SetString(PyExc_SystemError,
		                "GroupResult type not initialized");
		return NULL;
	}

	/* Build gr_mem tuple */
	int n = 0;
	if (gr->gr_mem != NULL)
		for (n = 0; gr->gr_mem[n] != NULL; n++);

	members = PyTuple_New(n);
	if (members == NULL)
		return NULL;

	for (i = 0; i < n; i++) {
		PyObject *s = PyUnicode_FromString(gr->gr_mem[i]);
		if (s == NULL) {
			Py_DECREF(members);
			return NULL;
		}
		PyTuple_SET_ITEM(members, i, s);
	}

	result = PyStructSequence_New((PyTypeObject *)state->GroupResultType);
	if (result == NULL) {
		Py_DECREF(members);
		return NULL;
	}

#define SET_FIELD(idx, expr) do {                   \
	PyObject *_v = (expr);                      \
	if (_v == NULL) {                           \
		Py_DECREF(members);                 \
		Py_DECREF(result);                  \
		return NULL;                        \
	}                                           \
	PyStructSequence_SET_ITEM(result, idx, _v); \
} while (0)

	SET_FIELD(GR_NAME, PyUnicode_FromString(gr->gr_name ? gr->gr_name : ""));
	SET_FIELD(GR_GID, PyLong_FromUnsignedLong((unsigned long)gr->gr_gid));
	/* members tuple ownership transferred to result */
	PyStructSequence_SET_ITEM(result, GR_MEM, members);
	SET_FIELD(GR_SOURCE, Py_NewRef(state->NssSourceMembers[mod_idx]));
	SET_FIELD(GR_LOCAL, PyBool_FromLong(mod_idx == NSS_MOD_FILES));

#undef SET_FIELD

	return result;
}

/* ── Low-level C wrappers ──────────────────────────────────────────────── */

/*
 * See pwd.c for the GIL-drop design rationale that applies equally here.
 */

static PyObject *
do_getgrnam(const char *name, int mod_idx)
{
	nss_fn_t fn;
	struct group gr;
	char *buf;
	size_t buflen = GROUP_INIT_BUFLEN;
	int nss_errno = 0;
	enum nss_status res = NSS_STATUS_UNAVAIL;

	if (!get_nss_fn(mod_idx, NSS_OP_GETGRNAM_R, &fn))
		return NULL;

	buf = PyMem_RawMalloc(buflen);
	if (buf == NULL)
		return PyErr_NoMemory();

	Py_BEGIN_ALLOW_THREADS
	while (1) {
		char *newbuf;


		nss_errno = 0;
		res = fn.getgrnam_r(name, &gr, buf, buflen, &nss_errno);

		if (nss_errno != ERANGE)
			break;

		newbuf = PyMem_RawRealloc(buf, buflen * 2);
		if (newbuf == NULL) {
			PyMem_RawFree(buf);
			buf = NULL;
			break;
		}
		buf = newbuf;
		buflen *= 2;
	}
	Py_END_ALLOW_THREADS

	if (buf == NULL)
		return PyErr_NoMemory();

	if (nss_errno != 0) {
		PyMem_RawFree(buf);
		raise_nss_error(nss_errno, "getgrnam_r", res, mod_idx);
		return NULL;
	}

	if (res == NSS_STATUS_NOTFOUND) {
		PyMem_RawFree(buf);
		Py_RETURN_NONE;
	}

	if (res != NSS_STATUS_SUCCESS) {
		PyMem_RawFree(buf);
		raise_nss_error(0, "getgrnam_r", res, mod_idx);
		return NULL;
	}

	PyObject *result = build_group_result(&gr, mod_idx);
	PyMem_RawFree(buf);
	return result;
}

static PyObject *
do_getgrgid(gid_t gid, int mod_idx)
{
	nss_fn_t fn;
	struct group gr;
	char *buf;
	size_t buflen = GROUP_INIT_BUFLEN;
	int nss_errno = 0;
	enum nss_status res = NSS_STATUS_UNAVAIL;

	if (!get_nss_fn(mod_idx, NSS_OP_GETGRGID_R, &fn))
		return NULL;

	buf = PyMem_RawMalloc(buflen);
	if (buf == NULL)
		return PyErr_NoMemory();

	Py_BEGIN_ALLOW_THREADS
	while (1) {
		char *newbuf;


		nss_errno = 0;
		res = fn.getgrgid_r(gid, &gr, buf, buflen, &nss_errno);

		if (nss_errno != ERANGE)
			break;

		newbuf = PyMem_RawRealloc(buf, buflen * 2);
		if (newbuf == NULL) {
			PyMem_RawFree(buf);
			buf = NULL;
			break;
		}
		buf = newbuf;
		buflen *= 2;
	}
	Py_END_ALLOW_THREADS

	if (buf == NULL)
		return PyErr_NoMemory();

	if (nss_errno != 0) {
		PyMem_RawFree(buf);
		raise_nss_error(nss_errno, "getgrgid_r", res, mod_idx);
		return NULL;
	}

	if (res == NSS_STATUS_NOTFOUND) {
		PyMem_RawFree(buf);
		Py_RETURN_NONE;
	}

	if (res != NSS_STATUS_SUCCESS) {
		PyMem_RawFree(buf);
		raise_nss_error(0, "getgrgid_r", res, mod_idx);
		return NULL;
	}

	PyObject *result = build_group_result(&gr, mod_idx);
	PyMem_RawFree(buf);
	return result;
}

static int
do_setgrent(int mod_idx)
{
	nss_fn_t fn;
	enum nss_status res;
	int saved_errno;

	if (!get_nss_fn(mod_idx, NSS_OP_SETGRENT, &fn))
		return -1;

	Py_BEGIN_ALLOW_THREADS
	errno = 0;
	res = fn.setgrent(0);
	saved_errno = errno;
	Py_END_ALLOW_THREADS

	if (res != NSS_STATUS_SUCCESS) {
		raise_nss_error(saved_errno, "setgrent", res, mod_idx);
		return -1;
	}
	return 0;
}

static int
do_endgrent(int mod_idx)
{
	nss_fn_t fn;
	enum nss_status res;
	int saved_errno;

	if (!get_nss_fn(mod_idx, NSS_OP_ENDGRENT, &fn))
		return -1;

	Py_BEGIN_ALLOW_THREADS
	errno = 0;
	res = fn.endgrent();
	saved_errno = errno;
	Py_END_ALLOW_THREADS

	if (res != NSS_STATUS_SUCCESS) {
		raise_nss_error(saved_errno, "endgrent", res, mod_idx);
		return -1;
	}
	return 0;
}

static PyObject *
do_getgrent(int mod_idx)
{
	nss_fn_t fn;
	struct group gr;
	char *buf;
	size_t buflen = GROUP_INIT_BUFLEN;
	int nss_errno = 0;
	enum nss_status res = NSS_STATUS_UNAVAIL;

	if (!get_nss_fn(mod_idx, NSS_OP_GETGRENT_R, &fn))
		return NULL;

	buf = PyMem_RawMalloc(buflen);
	if (buf == NULL)
		return PyErr_NoMemory();

	Py_BEGIN_ALLOW_THREADS
	while (1) {
		char *newbuf;


		nss_errno = 0;
		res = fn.getgrent_r(&gr, buf, buflen, &nss_errno);

		if (nss_errno != ERANGE)
			break;

		newbuf = PyMem_RawRealloc(buf, buflen * 2);
		if (newbuf == NULL) {
			PyMem_RawFree(buf);
			buf = NULL;
			break;
		}
		buf = newbuf;
		buflen *= 2;
	}
	Py_END_ALLOW_THREADS

	if (buf == NULL)
		return PyErr_NoMemory();

	if (nss_errno != 0) {
		PyMem_RawFree(buf);
		raise_nss_error(nss_errno, "getgrent_r", res, mod_idx);
		return NULL;
	}

	if (res != NSS_STATUS_SUCCESS) {
		PyMem_RawFree(buf);
		Py_RETURN_NONE;
	}

	PyObject *result = build_group_result(&gr, mod_idx);
	PyMem_RawFree(buf);
	return result;
}

/* ── NssGroupIter PyType ───────────────────────────────────────────────── */

static PyObject *
py_no_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	PyErr_Format(PyExc_TypeError,
	             "%.100s cannot be instantiated directly",
	             type->tp_name);
	return NULL;
}

typedef struct {
	PyObject_HEAD
	int mod_idx;
	bool setent_called;
	bool locked;
} NssGroupIter;

static void
nss_group_iter_close(NssGroupIter *self)
{
	if (self->setent_called) {
		self->setent_called = false;
		do_endgrent(self->mod_idx);
		PyErr_Clear();
	}
	if (self->locked) {
		self->locked = false;
		nss_iter_unlock(self->mod_idx);
	}
}

static void
nss_group_iter_finalize(NssGroupIter *self)
{
	nss_group_iter_close(self);
}

static void
nss_group_iter_dealloc(NssGroupIter *self)
{
	nss_group_iter_close(self);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
nss_group_iter_iternext(NssGroupIter *self)
{
	if (!self->setent_called)
		return NULL;

	PyObject *entry = do_getgrent(self->mod_idx);
	if (entry == NULL)
		return NULL;

	if (entry == Py_None) {
		Py_DECREF(entry);
		nss_group_iter_close(self);
		return NULL;
	}

	return entry;
}

static PyObject *
nss_group_iter_enter(NssGroupIter *self, PyObject *Py_UNUSED(args))
{
	return Py_NewRef(self);
}

static PyObject *
nss_group_iter_exit(NssGroupIter *self, PyObject *Py_UNUSED(args))
{
	nss_group_iter_close(self);
	Py_RETURN_FALSE;
}

static PyMethodDef nss_group_iter_methods[] = {
	{ "__enter__", (PyCFunction)nss_group_iter_enter, METH_NOARGS, NULL },
	{ "__exit__", (PyCFunction)nss_group_iter_exit, METH_VARARGS, NULL },
	{ NULL }
};

static PyTypeObject NssGroupIterType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "truenas_pynss.NssGroupIter",
	.tp_basicsize = sizeof(NssGroupIter),
	.tp_new = py_no_new,
	.tp_dealloc = (destructor)nss_group_iter_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_FINALIZE,
	.tp_finalize = (destructor)nss_group_iter_finalize,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)nss_group_iter_iternext,
	.tp_methods = nss_group_iter_methods,
};

/* ── Python-callable functions ─────────────────────────────────────────── */

PyObject *
py_getgrnam(PyObject *module, PyObject *args, PyObject *kwargs)
{
	const char *name;
	const char *module_str = "ALL";
	const char *kwnames[] = { "name", "nss_module", NULL };
	int mod_idx;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|$s",
	                                 discard_const_p(char *, kwnames),
	                                 &name, &module_str))
		return NULL;

	if (parse_module_name(module_str, &mod_idx) < 0)
		return NULL;

	if (mod_idx != NSS_MOD_ALL) {
		PyObject *result = do_getgrnam(name, mod_idx);
		if (result == NULL)
			return NULL;
		if (result == Py_None) {
			Py_DECREF(result);
			PyErr_Format(PyExc_KeyError,
			             "getgrnam(): name not found: '%s'", name);
			return NULL;
		}
		return result;
	}

	for (int i = 0; i < NSS_MOD_COUNT; i++) {
		PyObject *result = do_getgrnam(name, i);
		if (result == NULL) {
			if (nss_err_is_unavail())
				continue;
			return NULL;
		}
		if (result != Py_None)
			return result;
		Py_DECREF(result);
	}

	PyErr_Format(PyExc_KeyError,
	             "getgrnam(): name not found: '%s'", name);
	return NULL;
}

PyObject *
py_getgrgid(PyObject *module, PyObject *args, PyObject *kwargs)
{
	unsigned long gid_arg;
	const char *module_str = "ALL";
	const char *kwnames[] = { "gid", "nss_module", NULL };
	int mod_idx;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "k|$s",
	                                 discard_const_p(char *, kwnames),
	                                 &gid_arg, &module_str))
		return NULL;

	if (parse_module_name(module_str, &mod_idx) < 0)
		return NULL;

	gid_t gid = (gid_t)gid_arg;

	if (mod_idx != NSS_MOD_ALL) {
		PyObject *result = do_getgrgid(gid, mod_idx);
		if (result == NULL)
			return NULL;
		if (result == Py_None) {
			Py_DECREF(result);
			PyErr_Format(PyExc_KeyError,
			             "getgrgid(): gid not found: '%lu'", gid_arg);
			return NULL;
		}
		return result;
	}

	for (int i = 0; i < NSS_MOD_COUNT; i++) {
		PyObject *result = do_getgrgid(gid, i);
		if (result == NULL) {
			if (nss_err_is_unavail())
				continue;
			return NULL;
		}
		if (result != Py_None)
			return result;
		Py_DECREF(result);
	}

	PyErr_Format(PyExc_KeyError,
	             "getgrgid(): gid not found: '%lu'", gid_arg);
	return NULL;
}

PyObject *
py_itergrp(PyObject *module, PyObject *args, PyObject *kwargs)
{
	const char *module_str = "FILES";
	const char *kwnames[] = { "nss_module", NULL };
	int mod_idx;
	NssGroupIter *iter;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|$s",
	                                 discard_const_p(char *, kwnames),
	                                 &module_str))
		return NULL;

	if (parse_module_name(module_str, &mod_idx) < 0)
		return NULL;

	if (mod_idx == NSS_MOD_ALL) {
		PyErr_SetString(PyExc_ValueError,
		                "itergrp(): Please select one of: FILES, WINBIND, SSS");
		return NULL;
	}

	nss_iter_lock(mod_idx);

	if (do_setgrent(mod_idx) < 0) {
		nss_iter_unlock(mod_idx);
		return NULL;
	}

	iter = PyObject_New(NssGroupIter, &NssGroupIterType);
	if (iter == NULL) {
		do_endgrent(mod_idx);
		nss_iter_unlock(mod_idx);
		return NULL;
	}

	iter->mod_idx = mod_idx;
	iter->setent_called = true;
	iter->locked = true;

	return (PyObject *)iter;
}

/* ── Type registration ─────────────────────────────────────────────────── */

int
init_group_types(PyObject *module)
{
	truenas_pynss_state_t *state = get_truenas_pynss_state(module);
	if (state == NULL)
		return -1;

	state->GroupResultType =
	        (PyObject *)PyStructSequence_NewType(&group_result_desc);
	if (state->GroupResultType == NULL)
		return -1;

	if (PyModule_AddObjectRef(module, "GroupResult",
	                          state->GroupResultType) < 0)
		return -1;

	if (PyType_Ready(&NssGroupIterType) < 0)
		return -1;

	if (PyModule_AddObjectRef(module, "NssGroupIter",
	                          (PyObject *)&NssGroupIterType) < 0)
		return -1;

	return 0;
}
