#define PY_SSIZE_T_CLEAN
#include "truenas_pykrb5.h"

static PyStructSequence_Field authdatainfo_fields[] = {
	{"ad_type", "Authorization data type (integer)"},
	{"contents", "Authorization data contents (bytes)"},
	{NULL}
};

static PyStructSequence_Desc authdatainfo_desc = {
	.name = "truenas_pykrb5.AuthDataInfo",
	.doc = "Kerberos authorization data information",
	.fields = authdatainfo_fields,
	.n_in_sequence = 2
};

static PyTypeObject *AuthDataInfoType = NULL;

static void
tncc_creds_dealloc(py_tncc_creds_t *self)
{
	Py_BEGIN_ALLOW_THREADS
	if (self->ccache) {
		pthread_mutex_lock(&self->ccache->ctx_mutex);
		krb5_free_cred_contents(self->ccache->context, &self->creds);
		pthread_mutex_unlock(&self->ccache->ctx_mutex);
	}
	Py_END_ALLOW_THREADS
	Py_CLEAR(self->ccache);
	Py_CLEAR(self->timestamps.authtime);
	Py_CLEAR(self->timestamps.starttime);
	Py_CLEAR(self->timestamps.endtime);
	Py_CLEAR(self->timestamps.renew_till);
	Py_TYPE(self)->tp_free((PyObject *) self);
}

static int
tncc_creds_init(py_tncc_creds_t *self, PyObject *args, PyObject *kwds)
{
	PyErr_SetString(PyExc_TypeError, "CcacheCred objects cannot be created directly");
	return -1;
}

static PyObject *
tncc_creds_get_client_principal(py_tncc_creds_t *self, void *closure)
{
	char *client_name = NULL;
	PyObject *result = NULL;
	krb5_error_code code;
	tnkrb5_error_t error;

	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&self->ccache->ctx_mutex);
	code = krb5_unparse_name(self->ccache->context, self->creds.client, &client_name);
	if (code != 0) {
		tnkrb5_error(self->ccache->context, code, &error);
	}
	pthread_mutex_unlock(&self->ccache->ctx_mutex);
	Py_END_ALLOW_THREADS

	if (code != 0) {
		set_exc_from_krb5(&error, "Failed to unparse client principal");
		tnkrb5_error_free(&error);
		return NULL;
	}

	if (client_name) {
		result = PyUnicode_FromString(client_name);
		Py_BEGIN_ALLOW_THREADS
		pthread_mutex_lock(&self->ccache->ctx_mutex);
		krb5_free_unparsed_name(self->ccache->context, client_name);
		pthread_mutex_unlock(&self->ccache->ctx_mutex);
		Py_END_ALLOW_THREADS
	} else {
		result = Py_NewRef(Py_None);
	}

	return result;
}

static PyObject *
tncc_creds_get_server_principal(py_tncc_creds_t *self, void *closure)
{
	char *server_name = NULL;
	PyObject *result = NULL;
	krb5_error_code code;
	tnkrb5_error_t error;

	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&self->ccache->ctx_mutex);
	code = krb5_unparse_name(self->ccache->context, self->creds.server, &server_name);
	if (code != 0) {
		tnkrb5_error(self->ccache->context, code, &error);
	}
	pthread_mutex_unlock(&self->ccache->ctx_mutex);
	Py_END_ALLOW_THREADS

	if (code != 0) {
		set_exc_from_krb5(&error, "Failed to unparse server principal");
		tnkrb5_error_free(&error);
		return NULL;
	}

	if (server_name) {
		result = PyUnicode_FromString(server_name);
		Py_BEGIN_ALLOW_THREADS
		pthread_mutex_lock(&self->ccache->ctx_mutex);
		krb5_free_unparsed_name(self->ccache->context, server_name);
		pthread_mutex_unlock(&self->ccache->ctx_mutex);
		Py_END_ALLOW_THREADS
	} else {
		result = Py_NewRef(Py_None);
	}

	return result;
}

static PyObject *
tncc_creds_get_authtime(py_tncc_creds_t *self, void *closure)
{
	return Py_NewRef(self->timestamps.authtime);
}

static PyObject *
tncc_creds_get_starttime(py_tncc_creds_t *self, void *closure)
{
	return Py_NewRef(self->timestamps.starttime);
}

static PyObject *
tncc_creds_get_endtime(py_tncc_creds_t *self, void *closure)
{
	return Py_NewRef(self->timestamps.endtime);
}

static PyObject *
tncc_creds_get_renew_till(py_tncc_creds_t *self, void *closure)
{
	return Py_NewRef(self->timestamps.renew_till);
}

static PyObject *
tncc_creds_get_addresses(py_tncc_creds_t *self, void *closure)
{
	krb5_address **addresses = self->creds.addresses;

	/* Handle NULL addresses array */
	if (addresses == NULL) {
		return PyTuple_New(0);
	}

	/* Create list for addresses */
	PyObject *addr_list = PyList_New(0);
	if (addr_list == NULL)
		return NULL;

	/* Convert each address to AddressInfo and append to list */
	for (krb5_address **addr_ptr = addresses; *addr_ptr != NULL; addr_ptr++) {
		PyObject *addr_info = krb5_address_to_addressinfo((PyObject *)self->ccache->mod_ref, *addr_ptr);
		if (addr_info == NULL) {
			Py_DECREF(addr_list);
			return NULL;
		}
		if (PyList_Append(addr_list, addr_info) < 0) {
			Py_DECREF(addr_info);
			Py_DECREF(addr_list);
			return NULL;
		}
		Py_DECREF(addr_info);
	}

	/* Convert list to tuple */
	PyObject *addr_tuple = PyList_AsTuple(addr_list);
	Py_DECREF(addr_list);
	return addr_tuple;
}

static PyObject *
tncc_creds_get_keyblock(py_tncc_creds_t *self, void *closure)
{
	return krb5_keyblock_to_keyinfo((PyObject *)self->ccache->mod_ref, &self->creds.keyblock);
}

static PyObject *
tncc_creds_get_is_skey(py_tncc_creds_t *self, void *closure)
{
	return Py_NewRef(self->creds.is_skey ? Py_True : Py_False);
}

static PyObject *
tncc_creds_get_ticket_flags(py_tncc_creds_t *self, void *closure)
{
	truenas_pykrb5_state *state = get_module_state((PyObject *)self->ccache->mod_ref);
	if (state == NULL || state->krb5_tktflags == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "KRB5TktFlags type not initialized");
		return NULL;
	}

	/* Create ticket flags enum instance */
	return PyObject_CallFunction(state->krb5_tktflags, "l", (long)self->creds.ticket_flags);
}

static PyObject *
tncc_creds_get_authdata(py_tncc_creds_t *self, void *closure)
{
	krb5_authdata **authdata = self->creds.authdata;

	/* Handle NULL authdata array */
	if (authdata == NULL) {
		return PyTuple_New(0);
	}

	/* Create list for authdata entries */
	PyObject *authdata_list = PyList_New(0);
	if (authdata_list == NULL)
		return NULL;

	/* Convert each authdata entry to AuthDataInfo and append to list */
	for (krb5_authdata **authdata_ptr = authdata; *authdata_ptr != NULL; authdata_ptr++) {
		PyObject *authdata_info = krb5_authdata_to_authdatainfo((PyObject *)self->ccache->mod_ref, *authdata_ptr);
		if (authdata_info == NULL) {
			Py_DECREF(authdata_list);
			return NULL;
		}
		if (PyList_Append(authdata_list, authdata_info) < 0) {
			Py_DECREF(authdata_info);
			Py_DECREF(authdata_list);
			return NULL;
		}
		Py_DECREF(authdata_info);
	}

	/* Convert list to tuple */
	PyObject *authdata_tuple = PyList_AsTuple(authdata_list);
	Py_DECREF(authdata_list);
	return authdata_tuple;
}

static PyGetSetDef tncc_creds_getset[] = {
	{
		.name = "client_principal",
		.get = (getter)tncc_creds_get_client_principal,
		.doc = "Client's principal identifier"
	},
	{
		.name = "server_principal",
		.get = (getter)tncc_creds_get_server_principal,
		.doc = "Server's principal identifier"
	},
	{
		.name = "authtime",
		.get = (getter)tncc_creds_get_authtime,
		.doc = "Time at which KDC issued the initial ticket that corresponds to this ticket"
	},
	{
		.name = "starttime",
		.get = (getter)tncc_creds_get_starttime,
		.doc = "Optional in ticket, if not present, use authtime"
	},
	{
		.name = "endtime",
		.get = (getter)tncc_creds_get_endtime,
		.doc = "Ticket expiration time"
	},
	{
		.name = "renew_till",
		.get = (getter)tncc_creds_get_renew_till,
		.doc = "Latest time at which renewal of ticket can be valid"
	},
	{
		.name = "addresses",
		.get = (getter)tncc_creds_get_addresses,
		.doc = "Tuple of AddressInfo objects representing addresses in ticket"
	},
	{
		.name = "keyblock",
		.get = (getter)tncc_creds_get_keyblock,
		.doc = "Session encryption key used to encrypt the ticket (KeyInfo struct sequence)"
	},
	{
		.name = "is_skey",
		.get = (getter)tncc_creds_get_is_skey,
		.doc = "Whether this credential is for a service-to-service ticket"
	},
	{
		.name = "ticket_flags",
		.get = (getter)tncc_creds_get_ticket_flags,
		.doc = "Ticket flags as KRB5TktFlags enum"
	},
	{
		.name = "authdata",
		.get = (getter)tncc_creds_get_authdata,
		.doc = "Tuple of AuthDataInfo objects representing authorization data"
	},
	{NULL}
};

py_tncc_creds_t *
create_ccache_cred(py_tncc_t *ccache, krb5_creds *creds)
{
	py_tncc_creds_t *creds_obj;

	creds_obj = (py_tncc_creds_t *) PyType_GenericNew(&TruenasCcacheCredType, NULL, NULL);
	if (creds_obj == NULL)
		return NULL;

	/* Store reference to parent credential cache */
	creds_obj->ccache = (py_tncc_t *)Py_NewRef(ccache);

	/* Copy the credential data */
	creds_obj->creds = *creds;

	/* Initialize datetime objects for timestamps */
	creds_obj->timestamps.authtime = timestamp_to_datetime((PyObject *)ccache->mod_ref, creds->times.authtime);
	if (creds_obj->timestamps.authtime == NULL)
		goto error;

	creds_obj->timestamps.starttime = timestamp_to_datetime((PyObject *)ccache->mod_ref, creds->times.starttime);
	if (creds_obj->timestamps.starttime == NULL)
		goto error;

	creds_obj->timestamps.endtime = timestamp_to_datetime((PyObject *)ccache->mod_ref, creds->times.endtime);
	if (creds_obj->timestamps.endtime == NULL)
		goto error;

	creds_obj->timestamps.renew_till = timestamp_to_datetime((PyObject *)ccache->mod_ref, creds->times.renew_till);
	if (creds_obj->timestamps.renew_till == NULL)
		goto error;

	return creds_obj;

error:
	/*
	 * Zero the shallow-copied creds before releasing the object so that
	 * tncc_creds_dealloc does not free the heap-allocated fields (principal
	 * strings, key material, etc.) that are still owned by the caller.
	 */
	memset(&creds_obj->creds, 0, sizeof(creds_obj->creds));
	Py_DECREF(creds_obj);
	return NULL;
}

int
setup_authdatainfo_type(PyObject *mod)
{
	truenas_pykrb5_state *state = get_module_state(mod);
	if (state == NULL)
		return -1;

	state->authdatainfo_type = (PyObject *)PyStructSequence_NewType(&authdatainfo_desc);
	if (state->authdatainfo_type == NULL)
		return -1;

	AuthDataInfoType = (PyTypeObject *)state->authdatainfo_type;

	if (PyModule_AddObjectRef(mod, "AuthDataInfo", state->authdatainfo_type) < 0)
		return -1;

	return 0;
}

static PyMethodDef tncc_creds_methods[] = {
	{NULL, NULL, 0, NULL}
};

PyTypeObject TruenasCcacheCredType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "truenas_pykrb5.CcacheCred",
	.tp_doc = "Kerberos credential cache credential object",
	.tp_basicsize = sizeof(py_tncc_creds_t),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = py_no_new,
	.tp_dealloc = (destructor) tncc_creds_dealloc,
	.tp_methods = tncc_creds_methods,
	.tp_getset = tncc_creds_getset,
};