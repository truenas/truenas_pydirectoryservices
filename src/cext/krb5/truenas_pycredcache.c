#define _GNU_SOURCE
#define PY_SSIZE_T_CLEAN
#include "truenas_pykrb5.h"
#include <string.h>

static void
tncc_dealloc(py_tncc_t *self)
{
	Py_BEGIN_ALLOW_THREADS
	if (self->ccache) {
		krb5_cc_close(self->context, self->ccache);
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

int
tncc_init(py_tncc_t *self, PyObject *args, PyObject *kwds)
{
	char *ccache_name = NULL;
	const char *config_file = NULL;
	krb5_error_code ret;
	tnkrb5_error_t error;
	char ccache_name_buf[MAX_KEYTAB_NAME_LEN];

	static char *kwlist[] = {"ccache_name", "config_file", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|sz", kwlist, &ccache_name, &config_file))
		return -1;

	if (pthread_mutex_init(&self->ctx_mutex, NULL) != 0) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to initialize mutex");
		return -1;
	}

	Py_BEGIN_ALLOW_THREADS
	ret = init_context_with_config(config_file, &self->context);
	if (ret == 0) {
		if (ccache_name) {
			ret = krb5_cc_resolve(self->context, ccache_name, &self->ccache);
		} else {
			ret = krb5_cc_default(self->context, &self->ccache);
		}

		if (ret == 0) {
			const char *ccache_name_str = krb5_cc_get_name(self->context, self->ccache);
			if (ccache_name_str != NULL) {
				strncpy(ccache_name_buf, ccache_name_str, sizeof(ccache_name_buf) - 1);
				ccache_name_buf[sizeof(ccache_name_buf) - 1] = '\0';
			} else {
				ret = KRB5_CC_BADNAME;
			}
		}
	}
	if (ret) {
		tnkrb5_error(self->context, ret, &error);
	}
	Py_END_ALLOW_THREADS

	if (ret) {
		set_exc_from_krb5(&error, "Failed to open credential cache");
		tnkrb5_error_free(&error);
		return -1;
	}

	self->pyname = PyUnicode_FromString(ccache_name_buf);
	if (!self->pyname) {
		return -1;
	}

	return 0;
}

static PyObject *
tncc_iter(py_tncc_t *self)
{
	krb5_error_code ret;
	tnkrb5_error_t error;

	py_tncc_iter_t *iter = PyObject_New(py_tncc_iter_t, &TruenasCcacheIterType);
	if (iter == NULL)
		return NULL;

	Py_INCREF(self);
	iter->ccache = self;

	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&self->ctx_mutex);
	ret = krb5_cc_start_seq_get(self->context, self->ccache, &iter->cursor);
	if (ret)
		tnkrb5_error(self->context, ret, &error);
	pthread_mutex_unlock(&self->ctx_mutex);
	Py_END_ALLOW_THREADS

	if (ret) {
		set_exc_from_krb5(&error, "Failed to start credential cache iteration");
		tnkrb5_error_free(&error);
		Py_DECREF(iter);
		return NULL;
	}

	return (PyObject *)iter;
}

PyDoc_STRVAR(tncc_iter_credentials__doc__,
"iter_credentials() -> CcacheIter\n"
"--------------------------------\n\n"
"Create an iterator to iterate through all credentials in the credential cache.\n\n"
""
"Parameters\n"
"----------\n"
"None\n\n"
""
"Returns\n"
"-------\n"
"truenas_pykrb5.CcacheIter\n"
"    An iterator that yields credential objects for each credential in the cache.\n\n"
""
"Raises\n"
"------\n"
"RuntimeError:\n"
"    Failed to start credential cache iteration.\n\n"
);

static PyObject *
tncc_iter_credentials(py_tncc_t *self, PyObject *Py_UNUSED(ignored))
{
	return tncc_iter(self);
}

static PyObject *
tncc_get_name(py_tncc_t *self, void *Py_UNUSED(closure))
{
	return Py_NewRef(self->pyname);
}

static PyObject *
tncc_get_principal(py_tncc_t *self, void *Py_UNUSED(closure))
{
	krb5_principal princ = NULL;
	char *unparsed = NULL;
	PyObject *result = NULL;
	krb5_error_code code;
	tnkrb5_error_t error;

	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&self->ctx_mutex);
	code = krb5_cc_get_principal(self->context, self->ccache, &princ);
	if (code == 0) {
		code = krb5_unparse_name(self->context, princ, &unparsed);
		krb5_free_principal(self->context, princ);
		if (code != 0)
			tnkrb5_error(self->context, code, &error);
	} else {
		tnkrb5_error(self->context, code, &error);
	}
	pthread_mutex_unlock(&self->ctx_mutex);
	Py_END_ALLOW_THREADS

	if (code != 0) {
		set_exc_from_krb5(&error, "Failed to get default principal");
		tnkrb5_error_free(&error);
		return NULL;
	}

	result = PyUnicode_FromString(unparsed);
	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&self->ctx_mutex);
	krb5_free_unparsed_name(self->context, unparsed);
	pthread_mutex_unlock(&self->ctx_mutex);
	Py_END_ALLOW_THREADS

	return result;
}

PyDoc_STRVAR(tncc_kdestroy__doc__,
"kdestroy() -> None\n"
"---------\n\n"
"Destroy the credential cache, removing all credentials and the cache itself.\n\n"
"Raises\n"
"------\n"
"KRB5Error:\n"
"    Failed to destroy credential cache.\n\n"
);

static PyObject *
tncc_kdestroy(py_tncc_t *self, PyObject *Py_UNUSED(ignored))
{
	krb5_error_code code;
	tnkrb5_error_t error;

	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&self->ctx_mutex);
	code = krb5_cc_destroy(self->context, self->ccache);
	if (code != 0) {
		tnkrb5_error(self->context, code, &error);
	}
	pthread_mutex_unlock(&self->ctx_mutex);
	Py_END_ALLOW_THREADS

	if (code != 0) {
		set_exc_from_krb5(&error, "Failed to destroy credential cache");
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyMethodDef tncc_methods[] = {
	{
		.ml_name = "iter_credentials",
		.ml_meth = (PyCFunction)tncc_iter_credentials,
		.ml_flags = METH_NOARGS,
		.ml_doc = tncc_iter_credentials__doc__
	},
	{
		.ml_name = "kdestroy",
		.ml_meth = (PyCFunction)tncc_kdestroy,
		.ml_flags = METH_NOARGS,
		.ml_doc = tncc_kdestroy__doc__
	},
	{NULL, NULL, 0, NULL}
};

static PyGetSetDef tncc_getset[] = {
	{
		.name = "name",
		.get = (getter)tncc_get_name,
		.doc = "Credential cache name"
	},
	{
		.name = "principal",
		.get = (getter)tncc_get_principal,
		.doc = "Default principal of the credential cache"
	},
	{NULL}
};

PyTypeObject TruenasCcacheType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "truenas_pykrb5.Ccache",
	.tp_doc = "Kerberos credential cache object",
	.tp_basicsize = sizeof(py_tncc_t),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = py_no_new,
	.tp_dealloc = (destructor) tncc_dealloc,
	.tp_iter = (getiterfunc) tncc_iter,
	.tp_methods = tncc_methods,
	.tp_getset = tncc_getset,
};