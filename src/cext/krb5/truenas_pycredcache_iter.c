#define PY_SSIZE_T_CLEAN
#include "truenas_pykrb5.h"

static void
tncc_iter_dealloc(py_tncc_iter_t *self)
{
	Py_BEGIN_ALLOW_THREADS
	if (self->ccache) {
		pthread_mutex_lock(&self->ccache->ctx_mutex);
		krb5_cc_end_seq_get(self->ccache->context, self->ccache->ccache, &self->cursor);
		pthread_mutex_unlock(&self->ccache->ctx_mutex);
	}
	Py_END_ALLOW_THREADS
	Py_CLEAR(self->ccache);
	Py_TYPE(self)->tp_free((PyObject *) self);
}

static int
tncc_iter_init(py_tncc_iter_t *self, PyObject *args, PyObject *kwds)
{
	py_tncc_t *ccache = NULL;
	krb5_error_code ret;
	tnkrb5_error_t error;

	if (!PyArg_ParseTuple(args, "O!", &TruenasCcacheType, &ccache))
		return -1;

	Py_INCREF(ccache);
	self->ccache = ccache;

	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&ccache->ctx_mutex);
	ret = krb5_cc_start_seq_get(ccache->context, ccache->ccache, &self->cursor);
	if (ret) {
		tnkrb5_error(ccache->context, ret, &error);
	}
	pthread_mutex_unlock(&ccache->ctx_mutex);
	Py_END_ALLOW_THREADS

	if (ret) {
		set_exc_from_krb5(&error, "Failed to start credential cache iteration");
		tnkrb5_error_free(&error);
		Py_CLEAR(self->ccache);
		return -1;
	}

	return 0;
}

static PyObject *
tncc_iter_next(py_tncc_iter_t *self)
{
	py_tncc_creds_t *creds_obj;
	krb5_creds creds;
	krb5_error_code ret;
	tnkrb5_error_t error;

	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&self->ccache->ctx_mutex);
	ret = krb5_cc_next_cred(self->ccache->context, self->ccache->ccache, &self->cursor, &creds);
	/* Skip internal config-principal entries (e.g. X-CACHECONF:) */
	while (ret == 0 && krb5_is_config_principal(self->ccache->context, creds.server)) {
		krb5_free_cred_contents(self->ccache->context, &creds);
		ret = krb5_cc_next_cred(self->ccache->context, self->ccache->ccache, &self->cursor, &creds);
	}
	if (ret && ret != KRB5_CC_END) {
		tnkrb5_error(self->ccache->context, ret, &error);
	}
	pthread_mutex_unlock(&self->ccache->ctx_mutex);
	Py_END_ALLOW_THREADS

	if (ret) {
		if (ret == KRB5_CC_END) {
			PyErr_SetNone(PyExc_StopIteration);
		} else {
			set_exc_from_krb5(&error, "Failed to get next credential");
			tnkrb5_error_free(&error);
		}
		return NULL;
	}

	creds_obj = create_ccache_cred(self->ccache, &creds);
	if (creds_obj == NULL) {
		Py_BEGIN_ALLOW_THREADS
		pthread_mutex_lock(&self->ccache->ctx_mutex);
		krb5_free_cred_contents(self->ccache->context, &creds);
		pthread_mutex_unlock(&self->ccache->ctx_mutex);
		Py_END_ALLOW_THREADS
		return NULL;
	}

	return (PyObject *) creds_obj;
}

static PyObject *
tncc_iter_iter(PyObject *self)
{
	Py_INCREF(self);
	return self;
}

static PyMethodDef tncc_iter_methods[] = {
	{NULL, NULL, 0, NULL}
};

PyTypeObject TruenasCcacheIterType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "truenas_pykrb5.CcacheIter",
	.tp_doc = "Kerberos credential cache iterator object",
	.tp_basicsize = sizeof(py_tncc_iter_t),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = py_no_new,
	.tp_dealloc = (destructor) tncc_iter_dealloc,
	.tp_iter = tncc_iter_iter,
	.tp_iternext = (iternextfunc) tncc_iter_next,
	.tp_methods = tncc_iter_methods,
};