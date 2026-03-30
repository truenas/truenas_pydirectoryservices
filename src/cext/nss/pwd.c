// SPDX-License-Identifier: LGPL-3.0-or-later

#include <Python.h>
#include "common/includes.h"
#include "nss_state.h"
#include "nss_module.h"
#include "nss_pwd.h"

#define PASSWD_INIT_BUFLEN 1024

/* ── PasswdResult PyStructSequence ─────────────────────────────────────── */

enum {
	PW_NAME,
	PW_UID,
	PW_GID,
	PW_GECOS,
	PW_DIR,
	PW_SHELL,
	PW_SOURCE,
	PW_LOCAL,
	PW_FIELD_COUNT
};

static PyStructSequence_Field passwd_result_fields[] = {
	{ "pw_name", "Login name" },
	{ "pw_uid", "User ID" },
	{ "pw_gid", "Group ID" },
	{ "pw_gecos", "Real name / GECOS field" },
	{ "pw_dir", "Home directory" },
	{ "pw_shell", "Shell program" },
	{ "source", "NSS module that provided this entry (e.g. 'FILES')" },
	{ "local", "True if the entry was provided by the FILES module" },
	{ NULL }
};

static PyStructSequence_Desc passwd_result_desc = {
	.name = "truenas_pynss.PasswdResult",
	.doc = "Password database entry returned by NSS lookup",
	.fields = passwd_result_fields,
	.n_in_sequence = PW_FIELD_COUNT,
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

/* ── C-level passwd result builder ────────────────────────────────────── */

static PyObject *
build_passwd_result(const struct passwd *pw, int mod_idx)
{
	truenas_pynss_state_t *state = get_truenas_pynss_state(NULL);
	PyObject *result;

	if (state == NULL || state->PasswdResultType == NULL) {
		PyErr_SetString(PyExc_SystemError,
		                "PasswdResult type not initialized");
		return NULL;
	}

	result = PyStructSequence_New((PyTypeObject *)state->PasswdResultType);
	if (result == NULL)
		return NULL;

#define SET_FIELD(idx, expr) do {                \
	PyObject *_v = (expr);                   \
	if (_v == NULL) {                        \
		Py_DECREF(result);               \
		return NULL;                     \
	}                                        \
	PyStructSequence_SET_ITEM(result, idx, _v); \
} while (0)

	SET_FIELD(PW_NAME, PyUnicode_FromString(pw->pw_name ? pw->pw_name : ""));
	SET_FIELD(PW_UID, PyLong_FromUnsignedLong((unsigned long)pw->pw_uid));
	SET_FIELD(PW_GID, PyLong_FromUnsignedLong((unsigned long)pw->pw_gid));
	SET_FIELD(PW_GECOS, PyUnicode_FromString(pw->pw_gecos ? pw->pw_gecos : ""));
	SET_FIELD(PW_DIR, PyUnicode_FromString(pw->pw_dir ? pw->pw_dir : ""));
	SET_FIELD(PW_SHELL, PyUnicode_FromString(pw->pw_shell ? pw->pw_shell : ""));
	SET_FIELD(PW_SOURCE, Py_NewRef(state->NssSourceMembers[mod_idx]));
	SET_FIELD(PW_LOCAL, PyBool_FromLong(mod_idx == NSS_MOD_FILES));

#undef SET_FIELD

	return result;
}

/* ── Low-level C wrappers ──────────────────────────────────────────────── */

/*
 * Call _nss_{mod}_getpwnam_r.  Returns a new PasswdResult reference on
 * success, Py_None (new ref) on NOTFOUND, or NULL with exception on error.
 *
 * get_nss_fn() is called with the GIL held (it may set Python exceptions).
 * The NSS call itself runs without the GIL so other threads can proceed
 * while a module (e.g. SSS, WINBIND) performs IPC or network I/O.
 * PyMem_RawMalloc/Realloc/Free are used because they are safe without GIL.
 */
static PyObject *
do_getpwnam(const char *name, int mod_idx)
{
	nss_fn_t fn;
	struct passwd pw;
	char *buf;
	size_t buflen = PASSWD_INIT_BUFLEN;
	int nss_errno = 0;
	enum nss_status res = NSS_STATUS_UNAVAIL;

	if (!get_nss_fn(mod_idx, NSS_OP_GETPWNAM_R, &fn))
		return NULL;

	buf = PyMem_RawMalloc(buflen);
	if (buf == NULL)
		return PyErr_NoMemory();

	Py_BEGIN_ALLOW_THREADS
	while (1) {
		char *newbuf;


		nss_errno = 0;
		res = fn.getpwnam_r(name, &pw, buf, buflen, &nss_errno);

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
		raise_nss_error(nss_errno, "getpwnam_r", res, mod_idx);
		return NULL;
	}

	if (res == NSS_STATUS_NOTFOUND) {
		PyMem_RawFree(buf);
		Py_RETURN_NONE;
	}

	if (res != NSS_STATUS_SUCCESS) {
		PyMem_RawFree(buf);
		raise_nss_error(0, "getpwnam_r", res, mod_idx);
		return NULL;
	}

	PyObject *result = build_passwd_result(&pw, mod_idx);
	PyMem_RawFree(buf);
	return result;
}

/*
 * Call _nss_{mod}_getpwuid_r.
 */
static PyObject *
do_getpwuid(uid_t uid, int mod_idx)
{
	nss_fn_t fn;
	struct passwd pw;
	char *buf;
	size_t buflen = PASSWD_INIT_BUFLEN;
	int nss_errno = 0;
	enum nss_status res = NSS_STATUS_UNAVAIL;

	if (!get_nss_fn(mod_idx, NSS_OP_GETPWUID_R, &fn))
		return NULL;

	buf = PyMem_RawMalloc(buflen);
	if (buf == NULL)
		return PyErr_NoMemory();

	Py_BEGIN_ALLOW_THREADS
	while (1) {
		char *newbuf;


		nss_errno = 0;
		res = fn.getpwuid_r(uid, &pw, buf, buflen, &nss_errno);

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
		raise_nss_error(nss_errno, "getpwuid_r", res, mod_idx);
		return NULL;
	}

	if (res == NSS_STATUS_NOTFOUND) {
		PyMem_RawFree(buf);
		Py_RETURN_NONE;
	}

	if (res != NSS_STATUS_SUCCESS) {
		PyMem_RawFree(buf);
		raise_nss_error(0, "getpwuid_r", res, mod_idx);
		return NULL;
	}

	PyObject *result = build_passwd_result(&pw, mod_idx);
	PyMem_RawFree(buf);
	return result;
}

/*
 * Call _nss_{mod}_setpwent.  Returns 0 on success, -1 with exception on error.
 */
static int
do_setpwent(int mod_idx)
{
	nss_fn_t fn;
	enum nss_status res;
	int saved_errno;

	if (!get_nss_fn(mod_idx, NSS_OP_SETPWENT, &fn))
		return -1;

	Py_BEGIN_ALLOW_THREADS
	errno = 0;
	res = fn.setpwent(0);
	saved_errno = errno;
	Py_END_ALLOW_THREADS

	if (res != NSS_STATUS_SUCCESS) {
		raise_nss_error(saved_errno, "setpwent", res, mod_idx);
		return -1;
	}
	return 0;
}

/*
 * Call _nss_{mod}_endpwent.  Returns 0 on success, -1 with exception on error.
 */
static int
do_endpwent(int mod_idx)
{
	nss_fn_t fn;
	enum nss_status res;
	int saved_errno;

	if (!get_nss_fn(mod_idx, NSS_OP_ENDPWENT, &fn))
		return -1;

	Py_BEGIN_ALLOW_THREADS
	errno = 0;
	res = fn.endpwent();
	saved_errno = errno;
	Py_END_ALLOW_THREADS

	if (res != NSS_STATUS_SUCCESS) {
		raise_nss_error(saved_errno, "endpwent", res, mod_idx);
		return -1;
	}
	return 0;
}

/*
 * Call _nss_{mod}_getpwent_r.  Returns a new PasswdResult on success,
 * Py_None on end-of-enumeration, or NULL with exception on error.
 */
static PyObject *
do_getpwent(int mod_idx)
{
	nss_fn_t fn;
	struct passwd pw;
	char *buf;
	size_t buflen = PASSWD_INIT_BUFLEN;
	int nss_errno = 0;
	enum nss_status res = NSS_STATUS_UNAVAIL;

	if (!get_nss_fn(mod_idx, NSS_OP_GETPWENT_R, &fn))
		return NULL;

	buf = PyMem_RawMalloc(buflen);
	if (buf == NULL)
		return PyErr_NoMemory();

	Py_BEGIN_ALLOW_THREADS
	while (1) {
		char *newbuf;


		nss_errno = 0;
		res = fn.getpwent_r(&pw, buf, buflen, &nss_errno);

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
		raise_nss_error(nss_errno, "getpwent_r", res, mod_idx);
		return NULL;
	}

	if (res != NSS_STATUS_SUCCESS) {
		PyMem_RawFree(buf);
		Py_RETURN_NONE;
	}

	PyObject *result = build_passwd_result(&pw, mod_idx);
	PyMem_RawFree(buf);
	return result;
}

/* ── NssPasswdIter PyType ──────────────────────────────────────────────── */

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
} NssPasswdIter;

static void
nss_passwd_iter_close(NssPasswdIter *self)
{
	if (self->setent_called) {
		self->setent_called = false;
		do_endpwent(self->mod_idx);
		PyErr_Clear();
	}
	if (self->locked) {
		self->locked = false;
		nss_iter_unlock(self->mod_idx);
	}
}

static void
nss_passwd_iter_finalize(NssPasswdIter *self)
{
	nss_passwd_iter_close(self);
}

static void
nss_passwd_iter_dealloc(NssPasswdIter *self)
{
	nss_passwd_iter_close(self);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
nss_passwd_iter_iternext(NssPasswdIter *self)
{
	if (!self->setent_called)
		return NULL;

	PyObject *entry = do_getpwent(self->mod_idx);
	if (entry == NULL)
		return NULL;

	if (entry == Py_None) {
		Py_DECREF(entry);
		nss_passwd_iter_close(self);
		return NULL;
	}

	return entry;
}

static PyObject *
nss_passwd_iter_enter(NssPasswdIter *self, PyObject *Py_UNUSED(args))
{
	return Py_NewRef(self);
}

static PyObject *
nss_passwd_iter_exit(NssPasswdIter *self, PyObject *Py_UNUSED(args))
{
	nss_passwd_iter_close(self);
	Py_RETURN_FALSE;
}

static PyMethodDef nss_passwd_iter_methods[] = {
	{ "__enter__", (PyCFunction)nss_passwd_iter_enter, METH_NOARGS, NULL },
	{ "__exit__", (PyCFunction)nss_passwd_iter_exit, METH_VARARGS, NULL },
	{ NULL }
};

static PyTypeObject NssPasswdIterType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "truenas_pynss.NssPasswdIter",
	.tp_basicsize = sizeof(NssPasswdIter),
	.tp_new = py_no_new,
	.tp_dealloc = (destructor)nss_passwd_iter_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_FINALIZE,
	.tp_finalize = (destructor)nss_passwd_iter_finalize,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)nss_passwd_iter_iternext,
	.tp_methods = nss_passwd_iter_methods,
};

/* ── Python-callable functions ─────────────────────────────────────────── */

PyObject *
py_getpwnam(PyObject *module, PyObject *args, PyObject *kwargs)
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
		PyObject *result = do_getpwnam(name, mod_idx);
		if (result == NULL)
			return NULL;
		if (result == Py_None) {
			Py_DECREF(result);
			PyErr_Format(PyExc_KeyError,
			             "getpwnam(): name not found: '%s'", name);
			return NULL;
		}
		return result;
	}

	/* ALL: try each module in order, skip UNAVAIL errors */
	for (int i = 0; i < NSS_MOD_COUNT; i++) {
		PyObject *result = do_getpwnam(name, i);
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
	             "getpwnam(): name not found: '%s'", name);
	return NULL;
}

PyObject *
py_getpwuid(PyObject *module, PyObject *args, PyObject *kwargs)
{
	unsigned long uid_arg;
	const char *module_str = "ALL";
	const char *kwnames[] = { "uid", "nss_module", NULL };
	int mod_idx;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "k|$s",
	                                 discard_const_p(char *, kwnames),
	                                 &uid_arg, &module_str))
		return NULL;

	if (parse_module_name(module_str, &mod_idx) < 0)
		return NULL;

	uid_t uid = (uid_t)uid_arg;

	if (mod_idx != NSS_MOD_ALL) {
		PyObject *result = do_getpwuid(uid, mod_idx);
		if (result == NULL)
			return NULL;
		if (result == Py_None) {
			Py_DECREF(result);
			PyErr_Format(PyExc_KeyError,
			             "getpwuid(): uid not found: '%lu'", uid_arg);
			return NULL;
		}
		return result;
	}

	/* ALL: try each module in order, skip UNAVAIL errors */
	for (int i = 0; i < NSS_MOD_COUNT; i++) {
		PyObject *result = do_getpwuid(uid, i);
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
	             "getpwuid(): uid not found: '%lu'", uid_arg);
	return NULL;
}

PyObject *
py_iterpw(PyObject *module, PyObject *args, PyObject *kwargs)
{
	const char *module_str = "FILES";
	const char *kwnames[] = { "nss_module", NULL };
	int mod_idx;
	NssPasswdIter *iter;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|$s",
	                                 discard_const_p(char *, kwnames),
	                                 &module_str))
		return NULL;

	if (parse_module_name(module_str, &mod_idx) < 0)
		return NULL;

	if (mod_idx == NSS_MOD_ALL) {
		PyErr_SetString(PyExc_ValueError,
		                "iterpw(): Please select one of: FILES, WINBIND, SSS");
		return NULL;
	}

	nss_iter_lock(mod_idx);

	if (do_setpwent(mod_idx) < 0) {
		nss_iter_unlock(mod_idx);
		return NULL;
	}

	iter = PyObject_New(NssPasswdIter, &NssPasswdIterType);
	if (iter == NULL) {
		do_endpwent(mod_idx);
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
init_passwd_types(PyObject *module)
{
	truenas_pynss_state_t *state = get_truenas_pynss_state(module);
	if (state == NULL)
		return -1;

	/* Register PasswdResult PyStructSequence */
	state->PasswdResultType =
	        (PyObject *)PyStructSequence_NewType(&passwd_result_desc);
	if (state->PasswdResultType == NULL)
		return -1;

	if (PyModule_AddObjectRef(module, "PasswdResult",
	                          state->PasswdResultType) < 0)
		return -1;

	/* Register NssPasswdIter type */
	if (PyType_Ready(&NssPasswdIterType) < 0)
		return -1;

	if (PyModule_AddObjectRef(module, "NssPasswdIter",
	                          (PyObject *)&NssPasswdIterType) < 0)
		return -1;

	return 0;
}
