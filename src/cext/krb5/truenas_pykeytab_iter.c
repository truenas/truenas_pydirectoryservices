#define PY_SSIZE_T_CLEAN
#include "truenas_pykrb5.h"

static void
tnkt_iter_dealloc(py_tnkt_iter_t *self)
{
	Py_BEGIN_ALLOW_THREADS
	if (self->keytab) {
		pthread_mutex_lock(&self->keytab->ctx_mutex);
		krb5_kt_end_seq_get(self->keytab->context, self->keytab->keytab, &self->cursor);
		pthread_mutex_unlock(&self->keytab->ctx_mutex);
	}
	Py_END_ALLOW_THREADS
	Py_XDECREF(self->keytab);
	Py_TYPE(self)->tp_free((PyObject *) self);
}

static int
tnkt_iter_init(py_tnkt_iter_t *self, PyObject *args, PyObject *kwds)
{
	py_tnkt_t *keytab = NULL;
	krb5_error_code ret;
	tnkrb5_error_t error;

	if (!PyArg_ParseTuple(args, "O!", &TruenasKeytabType, &keytab))
		return -1;

	Py_INCREF(keytab);
	self->keytab = keytab;

	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&keytab->ctx_mutex);
	ret = krb5_kt_start_seq_get(keytab->context, keytab->keytab, &self->cursor);
	if (ret) {
		tnkrb5_error(keytab->context, ret, &error);
	}
	pthread_mutex_unlock(&keytab->ctx_mutex);
	Py_END_ALLOW_THREADS

	if (ret) {
		set_exc_from_krb5(&error, "Failed to start keytab iteration");
		tnkrb5_error_free(&error);
		Py_DECREF(keytab);
		self->keytab = NULL;
		return -1;
	}

	return 0;
}

static PyObject *
tnkt_iter_next(py_tnkt_iter_t *self)
{
	py_tnkt_entry_t *entry_obj;
	krb5_keytab_entry entry;
	krb5_error_code ret;
	tnkrb5_error_t error;

	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&self->keytab->ctx_mutex);
	ret = krb5_kt_next_entry(self->keytab->context, self->keytab->keytab, &entry, &self->cursor);
	if (ret && ret != KRB5_KT_END) {
		tnkrb5_error(self->keytab->context, ret, &error);
	}
	pthread_mutex_unlock(&self->keytab->ctx_mutex);
	Py_END_ALLOW_THREADS

	if (ret) {
		if (ret == KRB5_KT_END) {
			PyErr_SetNone(PyExc_StopIteration);
		} else {
			set_exc_from_krb5(&error, "Failed to get next keytab entry");
			tnkrb5_error_free(&error);
		}
		return NULL;
	}

	entry_obj = create_keytab_entry(self->keytab, &entry);
	if (entry_obj == NULL) {
		Py_BEGIN_ALLOW_THREADS
		pthread_mutex_lock(&self->keytab->ctx_mutex);
		krb5_free_keytab_entry_contents(self->keytab->context, &entry);
		pthread_mutex_unlock(&self->keytab->ctx_mutex);
		Py_END_ALLOW_THREADS
		return NULL;
	}

	return (PyObject *) entry_obj;
}

static PyObject *
tnkt_iter_iter(PyObject *self)
{
	Py_INCREF(self);
	return self;
}

static PyMethodDef tnkt_iter_methods[] = {
	{NULL, NULL, 0, NULL}
};

PyTypeObject TruenasKeytabIterType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "truenas_pykrb5.KeytabIter",
	.tp_doc = "Kerberos keytab iterator object",
	.tp_basicsize = sizeof(py_tnkt_iter_t),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = py_no_new,
	.tp_dealloc = (destructor) tnkt_iter_dealloc,
	.tp_iter = tnkt_iter_iter,
	.tp_iternext = (iternextfunc) tnkt_iter_next,
	.tp_methods = tnkt_iter_methods,
};