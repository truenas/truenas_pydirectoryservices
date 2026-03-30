#define _GNU_SOURCE
#define PY_SSIZE_T_CLEAN
#include <sys/mman.h>
#include <unistd.h>
#include "truenas_pykrb5.h"

static void
tnkt_dealloc(py_tnkt_t *self)
{
	Py_BEGIN_ALLOW_THREADS
	if (self->keytab) {
		krb5_kt_close(self->context, self->keytab);
	}
	if (self->tnmemkt) {
		fclose(self->tnmemkt);
	}
	if (self->context) {
		krb5_free_context(self->context);
	}
	pthread_mutex_destroy(&self->ctx_mutex);
	Py_END_ALLOW_THREADS
	Py_XDECREF(self->mod_ref);
	Py_XDECREF(self->pyname);
	Py_TYPE(self)->tp_free((PyObject *) self);
}

/*
 *  Convert arbitrary python bytes data into an in-memory FILE that can
 *  be resolved by krb5 library for keytab parsing
 */
static krb5_error_code
tnkt_resolve_memfd(py_tnkt_t *self, const char *data, Py_ssize_t datalen)
{
	int memfd;
	char procfd_path[64];

	memfd = memfd_create("keytab", MFD_CLOEXEC);
	if (memfd == -1) {
		return KRB5KRB_ERR_GENERIC;
	}


	self->tnmemkt = fdopen(memfd, "w+b");
	if (!self->tnmemkt) {
		close(memfd);
		return KRB5KRB_ERR_GENERIC;
	}

	if (fwrite(data, 1, datalen, self->tnmemkt) != (size_t)datalen) {
		fclose(self->tnmemkt);
		self->tnmemkt = NULL;
		return KRB5KRB_ERR_GENERIC;
	}

	fflush(self->tnmemkt);
	snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d", memfd);
	return krb5_kt_resolve(self->context, procfd_path, &self->keytab);
}

int
tnkt_init(py_tnkt_t *self, PyObject *args, PyObject *kwds)
{
	char *filename = NULL;
	const char *data = NULL;
	Py_ssize_t datalen = 0;
	krb5_error_code ret;
	tnkrb5_error_t error;

	static char *kwlist[] = {"filename", "data", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$sy#", kwlist, &filename, &data, &datalen))
		return -1;

	if (filename && data) {
		PyErr_SetString(PyExc_ValueError, "Cannot specify both filename and data");
		return -1;
	}

	if (pthread_mutex_init(&self->ctx_mutex, NULL) != 0) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to initialize mutex");
		return -1;
	}

	char keytab_name[MAX_KEYTAB_NAME_LEN];

	Py_BEGIN_ALLOW_THREADS
	ret = krb5_init_context(&self->context);
	if (ret == 0) {
		if (filename) {
			ret = krb5_kt_resolve(self->context, filename,
			                      &self->keytab);
		} else if (data) {
			ret = tnkt_resolve_memfd(self, data, datalen);
		} else {
			ret = krb5_kt_default(self->context, &self->keytab);
		}

		if (ret == 0) {
			ret = krb5_kt_get_name(self->context, self->keytab, keytab_name, sizeof(keytab_name));
		}
	}
	if (ret) {
		tnkrb5_error(self->context, ret, &error);
	}
	Py_END_ALLOW_THREADS

	if (ret) {
		set_exc_from_krb5(&error, "Failed to open keytab");
		tnkrb5_error_free(&error);
		return -1;
	}

	self->pyname = PyUnicode_FromString(keytab_name);
	if (!self->pyname) {
		return -1;
	}

	return 0;
}

static PyObject *
tnkt_iter(py_tnkt_t *self)
{
	krb5_error_code ret;
	tnkrb5_error_t error;

	py_tnkt_iter_t *iter = PyObject_New(py_tnkt_iter_t, &TruenasKeytabIterType);
	if (iter == NULL)
		return NULL;

	Py_INCREF(self);
	iter->keytab = self;

	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&self->ctx_mutex);
	ret = krb5_kt_start_seq_get(self->context, self->keytab, &iter->cursor);
	if (ret)
		tnkrb5_error(self->context, ret, &error);
	pthread_mutex_unlock(&self->ctx_mutex);
	Py_END_ALLOW_THREADS

	if (ret) {
		set_exc_from_krb5(&error, "Failed to start keytab iteration");
		tnkrb5_error_free(&error);
		Py_DECREF(iter);
		return NULL;
	}

	return (PyObject *)iter;
}

PyDoc_STRVAR(tnkt_iter_keytab__doc__,
"iter_keytab() -> KeytabIter\n"
"--------------------------\n\n"
"Create an iterator to iterate through all entries in the keytab.\n\n"
""
"Parameters\n"
"----------\n"
"None\n\n"
""
"Returns\n"
"-------\n"
"truenas_pykrb5.KeytabIter\n"
"    An iterator that yields KeytabEntry objects for each entry in the keytab.\n\n"
""
"Raises\n"
"------\n"
"RuntimeError:\n"
"    Failed to start keytab iteration.\n\n"
);

static PyObject *
tnkt_iter_keytab(py_tnkt_t *self, PyObject *Py_UNUSED(ignored))
{
	return tnkt_iter(self);
}

static PyObject *
tnkt_get_name(py_tnkt_t *self, void *Py_UNUSED(closure))
{
	return Py_NewRef(self->pyname);
}

/* ── add_entry ─────────────────────────────────────────────────────────── */

PyDoc_STRVAR(tnkt_add_entry__doc__,
"add_entry(*, principal, enctype, vno=0, password=None, key=None) -> None\n"
"--\n\n"
"Add an entry to the keytab.\n\n"
"Exactly one of password or key must be provided.\n"
"If password is given, the key is derived via string-to-key.\n"
"If key is given, raw key bytes are used directly.\n"
);

static PyObject *
tnkt_add_entry(py_tnkt_t *self, PyObject *args, PyObject *kwds)
{
	const char *principal_str = NULL;
	int enctype = 0;
	int vno = 0;
	const char *password = NULL;
	const char *key_data = NULL;
	Py_ssize_t key_len = 0;
	static char *kwlist[] = {
		"principal", "enctype", "vno", "password", "key", NULL
	};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$siisy#", kwlist,
	                                 &principal_str, &enctype, &vno,
	                                 &password, &key_data, &key_len))
		return NULL;

	if (principal_str == NULL || enctype == 0) {
		PyErr_SetString(PyExc_TypeError,
		                "add_entry() requires 'principal' and 'enctype'");
		return NULL;
	}

	if ((password == NULL) == (key_data == NULL)) {
		PyErr_SetString(PyExc_ValueError,
		                "Exactly one of 'password' or 'key' must be provided");
		return NULL;
	}

	krb5_error_code ret;
	tnkrb5_error_t error;
	krb5_principal princ = NULL;
	krb5_keytab_entry entry;
	krb5_keyblock keyblock;
	int keyblock_valid = 0;

	memset(&entry, 0, sizeof(entry));
	memset(&keyblock, 0, sizeof(keyblock));

	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&self->ctx_mutex);

	ret = krb5_parse_name(self->context, principal_str, &princ);
	if (ret)
		goto done;

	if (password != NULL) {
		krb5_data pw_data, salt;

		pw_data.data = (char *)password;
		pw_data.length = strlen(password);

		ret = krb5_principal2salt(self->context, princ, &salt);
		if (ret)
			goto done;

		ret = krb5_c_string_to_key(self->context,
		                           (krb5_enctype)enctype,
		                           &pw_data, &salt, &keyblock);
		krb5_free_data_contents(self->context, &salt);
		if (ret)
			goto done;

		keyblock_valid = 1;
	} else {
		keyblock.enctype = (krb5_enctype)enctype;
		keyblock.length = (unsigned int)key_len;
		keyblock.contents = (krb5_octet *)key_data;
	}

	entry.principal = princ;
	entry.vno = (krb5_kvno)vno;
	ret = krb5_timeofday(self->context, &entry.timestamp);
	if (ret)
		goto done;

	entry.key = keyblock;
	ret = krb5_kt_add_entry(self->context, self->keytab, &entry);

done:
	if (ret)
		tnkrb5_error(self->context, ret, &error);
	if (keyblock_valid)
		krb5_free_keyblock_contents(self->context, &keyblock);
	if (princ)
		krb5_free_principal(self->context, princ);

	pthread_mutex_unlock(&self->ctx_mutex);
	Py_END_ALLOW_THREADS

	if (ret) {
		set_exc_from_krb5(&error, "Failed to add keytab entry");
		tnkrb5_error_free(&error);
		return NULL;
	}

	Py_RETURN_NONE;
}

/* ── remove_entry ──────────────────────────────────────────────────────── */

PyDoc_STRVAR(tnkt_remove_entry__doc__,
"remove_entry(*, principal, enctype=None, vno=None) -> None\n"
"--\n\n"
"Remove matching entries from the keytab.\n\n"
"If enctype or vno is None, all entries matching the other fields are removed.\n"
);

static PyObject *
tnkt_remove_entry(py_tnkt_t *self, PyObject *args, PyObject *kwds)
{
	const char *principal_str = NULL;
	PyObject *py_enctype = Py_None;
	PyObject *py_vno = Py_None;
	static char *kwlist[] = {"principal", "enctype", "vno", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$sOO", kwlist,
	                                 &principal_str, &py_enctype, &py_vno))
		return NULL;

	if (principal_str == NULL) {
		PyErr_SetString(PyExc_TypeError,
		                "remove_entry() requires 'principal'");
		return NULL;
	}

	int has_enctype = (py_enctype != Py_None);
	int has_vno = (py_vno != Py_None);
	krb5_enctype enctype = 0;
	krb5_kvno vno = 0;

	if (has_enctype) {
		enctype = (krb5_enctype)PyLong_AsLong(py_enctype);
		if (PyErr_Occurred())
			return NULL;
	}
	if (has_vno) {
		vno = (krb5_kvno)PyLong_AsUnsignedLong(py_vno);
		if (PyErr_Occurred())
			return NULL;
	}

	krb5_error_code ret;
	tnkrb5_error_t error;
	krb5_principal princ = NULL;

	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&self->ctx_mutex);

	ret = krb5_parse_name(self->context, principal_str, &princ);
	if (ret)
		goto done;

	if (has_enctype && has_vno) {
		krb5_keytab_entry entry;

		memset(&entry, 0, sizeof(entry));
		entry.principal = princ;
		entry.vno = vno;
		entry.key.enctype = enctype;

		ret = krb5_kt_remove_entry(self->context, self->keytab, &entry);
	} else {
		/* Wildcard: iterate and remove all matching */
		krb5_kt_cursor cursor;
		krb5_keytab_entry cur;

		ret = krb5_kt_start_seq_get(self->context, self->keytab, &cursor);
		if (ret)
			goto done;

		while (krb5_kt_next_entry(self->context, self->keytab,
		                          &cur, &cursor) == 0) {
			int match = krb5_principal_compare(self->context,
			                                   princ, cur.principal);
			if (match && has_enctype && cur.key.enctype != enctype)
				match = 0;
			if (match && has_vno && cur.vno != vno)
				match = 0;

			if (match) {
				/* End iteration before modifying */
				krb5_kt_end_seq_get(self->context, self->keytab,
				                    &cursor);
				ret = krb5_kt_remove_entry(self->context,
				                           self->keytab, &cur);
				krb5_free_keytab_entry_contents(self->context, &cur);

				if (ret)
					goto done;

				/* Restart iteration (keytab modified) */
				ret = krb5_kt_start_seq_get(self->context,
				                            self->keytab, &cursor);
				if (ret)
					goto done;
				continue;
			}
			krb5_free_keytab_entry_contents(self->context, &cur);
		}
		krb5_kt_end_seq_get(self->context, self->keytab, &cursor);
	}

done:
	if (ret)
		tnkrb5_error(self->context, ret, &error);
	if (princ)
		krb5_free_principal(self->context, princ);

	pthread_mutex_unlock(&self->ctx_mutex);
	Py_END_ALLOW_THREADS

	if (ret) {
		set_exc_from_krb5(&error, "Failed to remove keytab entry");
		tnkrb5_error_free(&error);
		return NULL;
	}

	Py_RETURN_NONE;
}

/* ── as_bytes ──────────────────────────────────────────────────────────── */

PyDoc_STRVAR(tnkt_as_bytes__doc__,
"as_bytes() -> bytes\n"
"--\n\n"
"Export the keytab contents as bytes.\n"
);

static PyObject *
tnkt_as_bytes(py_tnkt_t *self, PyObject *Py_UNUSED(ignored))
{
	krb5_error_code ret;
	tnkrb5_error_t error;
	int memfd = -1;
	krb5_keytab out_kt = NULL;
	krb5_kt_cursor cursor;
	krb5_keytab_entry entry;
	int cursor_active = 0;
	char path[128];
	off_t size;
	char *buf = NULL;
	PyObject *result = NULL;

	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&self->ctx_mutex);

	memfd = memfd_create("keytab_export", MFD_CLOEXEC);
	if (memfd == -1) {
		ret = KRB5KRB_ERR_GENERIC;
		goto done;
	}

	/*
	 * Write the keytab v2 file header (0x05 0x02) so that
	 * krb5_kt_resolve sees a valid keytab before any entries are added.
	 */
	{
		unsigned char hdr[2] = { 0x05, 0x02 };
		if (write(memfd, hdr, 2) != 2) {
			ret = KRB5KRB_ERR_GENERIC;
			goto done;
		}
	}

	snprintf(path, sizeof(path),
	         "/proc/self/fd/%d", memfd);
	ret = krb5_kt_resolve(self->context, path, &out_kt);
	if (ret)
		goto done;

	ret = krb5_kt_start_seq_get(self->context, self->keytab, &cursor);
	if (ret)
		goto done;
	cursor_active = 1;

	while ((ret = krb5_kt_next_entry(self->context, self->keytab,
	                                 &entry, &cursor)) == 0) {
		krb5_error_code add_ret;
		add_ret = krb5_kt_add_entry(self->context, out_kt, &entry);
		krb5_free_keytab_entry_contents(self->context, &entry);
		if (add_ret) {
			ret = add_ret;
			goto done;
		}
	}

	if (ret == KRB5_KT_END)
		ret = 0;

done:
	if (cursor_active)
		krb5_kt_end_seq_get(self->context, self->keytab, &cursor);
	if (out_kt)
		krb5_kt_close(self->context, out_kt);

	if (ret)
		tnkrb5_error(self->context, ret, &error);

	if (ret == 0 && memfd >= 0) {
		size = lseek(memfd, 0, SEEK_END);
		if (size <= 0) {
			ret = KRB5KRB_ERR_GENERIC;
			tnkrb5_error(self->context, ret, &error);
		} else {
			lseek(memfd, 0, SEEK_SET);
			buf = PyMem_RawMalloc((size_t)size);
			if (buf != NULL) {
				ssize_t nread = read(memfd, buf, (size_t)size);
				if (nread != size) {
					PyMem_RawFree(buf);
					buf = NULL;
					ret = KRB5KRB_ERR_GENERIC;
					tnkrb5_error(self->context, ret, &error);
				}
			}
		}
	}

	if (memfd >= 0)
		close(memfd);

	pthread_mutex_unlock(&self->ctx_mutex);
	Py_END_ALLOW_THREADS

	if (ret) {
		set_exc_from_krb5(&error, "Failed to export keytab");
		tnkrb5_error_free(&error);
		return NULL;
	}

	if (buf == NULL)
		return PyErr_NoMemory();

	result = PyBytes_FromStringAndSize(buf, (Py_ssize_t)size);
	PyMem_RawFree(buf);
	return result;
}

static PyMethodDef tnkt_methods[] = {
	{
		.ml_name = "iter_keytab",
		.ml_meth = (PyCFunction)tnkt_iter_keytab,
		.ml_flags = METH_NOARGS,
		.ml_doc = tnkt_iter_keytab__doc__
	},
	{
		.ml_name = "add_entry",
		.ml_meth = (PyCFunction)tnkt_add_entry,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = tnkt_add_entry__doc__
	},
	{
		.ml_name = "remove_entry",
		.ml_meth = (PyCFunction)tnkt_remove_entry,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = tnkt_remove_entry__doc__
	},
	{
		.ml_name = "as_bytes",
		.ml_meth = (PyCFunction)tnkt_as_bytes,
		.ml_flags = METH_NOARGS,
		.ml_doc = tnkt_as_bytes__doc__
	},
	{NULL, NULL, 0, NULL}
};

static PyGetSetDef tnkt_getset[] = {
	{
		.name = "name",
		.get = (getter)tnkt_get_name,
		.doc = "Keytab name/path"
	},
	{NULL}
};

PyTypeObject TruenasKeytabType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "truenas_pykrb5.Keytab",
	.tp_doc = "Kerberos keytab object",
	.tp_basicsize = sizeof(py_tnkt_t),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = py_no_new,
	.tp_dealloc = (destructor) tnkt_dealloc,
	.tp_iter = (getiterfunc) tnkt_iter,
	.tp_methods = tnkt_methods,
	.tp_getset = tnkt_getset,
};
