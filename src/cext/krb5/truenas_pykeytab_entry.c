#define PY_SSIZE_T_CLEAN
#include "truenas_pykrb5.h"

static void
tnkt_entry_dealloc(py_tnkt_entry_t *self)
{
	Py_BEGIN_ALLOW_THREADS
	if (self->keytab) {
		pthread_mutex_lock(&self->keytab->ctx_mutex);
		krb5_free_keytab_entry_contents(self->keytab->context, &self->entry);
		pthread_mutex_unlock(&self->keytab->ctx_mutex);
	}
	Py_END_ALLOW_THREADS
	Py_XDECREF(self->keytab);
	Py_CLEAR(self->timestamp);
	Py_TYPE(self)->tp_free((PyObject *) self);
}

static int
tnkt_entry_init(py_tnkt_entry_t *self, PyObject *args, PyObject *kwds)
{
	PyErr_SetString(PyExc_TypeError, "KeytabEntry objects cannot be created directly");
	return -1;
}

static PyObject *
tnkt_entry_get_timestamp(py_tnkt_entry_t *self, void *closure)
{
	return Py_NewRef(self->timestamp);
}

static PyObject *
tnkt_entry_get_vno(py_tnkt_entry_t *self, void *closure)
{
	return PyLong_FromLong((long)self->entry.vno);
}

static PyStructSequence_Field keyinfo_fields[] = {
	{"enctype", "Encryption type (KRB5EncType enum)"},
	{"contents", "Raw key data"},
	{"deprecated", "Whether this encryption type is deprecated"},
	{NULL}
};

static PyStructSequence_Desc keyinfo_desc = {
	.name = "truenas_pykrb5.KeyInfo",
	.doc = "Kerberos key information",
	.fields = keyinfo_fields,
	.n_in_sequence = 3
};

static PyStructSequence_Field principalinfo_fields[] = {
	{"realm", "Kerberos realm (string)"},
	{"components", "Principal name components (tuple of strings)"},
	{"principal_type", "Principal name type (KRB5PrincipalType enum)"},
	{NULL}
};

static PyStructSequence_Desc principalinfo_desc = {
	.name = "truenas_pykrb5.PrincipalInfo",
	.doc = "Kerberos principal information",
	.fields = principalinfo_fields,
	.n_in_sequence = 3
};

static PyStructSequence_Field addressinfo_fields[] = {
	{"addrtype", "Address type name (string)"},
	{"contents", "Address contents (bytes)"},
	{NULL}
};

static PyStructSequence_Desc addressinfo_desc = {
	.name = "truenas_pykrb5.AddressInfo",
	.doc = "Kerberos address information",
	.fields = addressinfo_fields,
	.n_in_sequence = 2
};

static PyTypeObject *KeyInfoType = NULL;
static PyTypeObject *PrincipalInfoType = NULL;
static PyTypeObject *AddressInfoType = NULL;

static PyObject *
tnkt_entry_get_secret_key(py_tnkt_entry_t *self, void *closure)
{
	return krb5_keyblock_to_keyinfo((PyObject *)self->keytab->mod_ref, &self->entry.key);
}

static PyObject *
tnkt_entry_get_principal(py_tnkt_entry_t *self, void *closure)
{
	PyObject *principalinfo;
	PyObject *realm = NULL;
	PyObject *components = NULL;
	PyObject *principal_type_obj = NULL;
	PyObject *module = NULL;
	PyObject *principal_type_enum = NULL;
	krb5_principal principal;
	int i;

	if (PrincipalInfoType == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "PrincipalInfo type not initialized");
		return NULL;
	}

	principalinfo = PyStructSequence_New(PrincipalInfoType);
	if (principalinfo == NULL)
		return NULL;

	principal = self->entry.principal;

	/* Create realm string */
	if (principal->realm.data && principal->realm.length > 0) {
		realm = PyUnicode_FromStringAndSize(principal->realm.data, principal->realm.length);
		if (realm == NULL)
			goto error;
	} else {
		realm = Py_None;
		Py_INCREF(Py_None);
	}
	PyStructSequence_SET_ITEM(principalinfo, 0, realm);

	/* Create components tuple */
	components = PyTuple_New(principal->length);
	if (components == NULL)
		goto error;

	for (i = 0; i < principal->length; i++) {
		PyObject *component;
		if (principal->data[i].data && principal->data[i].length > 0) {
			component = PyUnicode_FromStringAndSize(principal->data[i].data,
								principal->data[i].length);
		} else {
			component = PyUnicode_FromString("");
		}
		if (component == NULL) {
			Py_DECREF(components);
			goto error;
		}
		PyTuple_SET_ITEM(components, i, component);
	}
	PyStructSequence_SET_ITEM(principalinfo, 1, components);

	/* Get the KRB5PrincipalType enum from module */
	module = PyImport_ImportModule("truenas_pykrb5");
	if (module == NULL)
		goto error;

	principal_type_enum = PyObject_GetAttrString(module, "KRB5PrincipalType");
	Py_DECREF(module);
	if (principal_type_enum == NULL)
		goto error;

	/* Create principal type enum instance */
	principal_type_obj = PyObject_CallFunction(principal_type_enum, "i", (int)principal->type);
	Py_DECREF(principal_type_enum);
	if (principal_type_obj == NULL)
		goto error;

	PyStructSequence_SET_ITEM(principalinfo, 2, principal_type_obj);

	return principalinfo;

error:
	Py_DECREF(principalinfo);
	return NULL;
}

static PyGetSetDef tnkt_entry_getsetters[] = {
	{
		.name = "timestamp",
		.get = (getter) tnkt_entry_get_timestamp,
		.doc = "Time entry written to keytable (Unix timestamp)"
	},
	{
		.name = "vno",
		.get = (getter) tnkt_entry_get_vno,
		.doc = "Key version number"
	},
	{
		.name = "secret_key",
		.get = (getter) tnkt_entry_get_secret_key,
		.doc = "Secret key information (KeyInfo struct sequence)"
	},
	{
		.name = "principal",
		.get = (getter) tnkt_entry_get_principal,
		.doc = "Principal information (PrincipalInfo struct sequence)"
	},
	{NULL}
};

int
setup_keyinfo_type(PyObject *mod)
{
	truenas_pykrb5_state *state = get_module_state(mod);
	if (state == NULL)
		return -1;

	state->keyinfo_type = (PyObject *)PyStructSequence_NewType(&keyinfo_desc);
	if (state->keyinfo_type == NULL)
		return -1;

	KeyInfoType = (PyTypeObject *)state->keyinfo_type;

	if (PyModule_AddObjectRef(mod, "KeyInfo", state->keyinfo_type) < 0)
		return -1;

	return 0;
}

int
setup_principalinfo_type(PyObject *mod)
{
	truenas_pykrb5_state *state = get_module_state(mod);
	if (state == NULL)
		return -1;

	state->principalinfo_type = (PyObject *)PyStructSequence_NewType(&principalinfo_desc);
	if (state->principalinfo_type == NULL)
		return -1;

	PrincipalInfoType = (PyTypeObject *)state->principalinfo_type;

	if (PyModule_AddObjectRef(mod, "PrincipalInfo", state->principalinfo_type) < 0)
		return -1;

	return 0;
}

int
setup_addressinfo_type(PyObject *mod)
{
	truenas_pykrb5_state *state = get_module_state(mod);
	if (state == NULL)
		return -1;

	state->addressinfo_type = (PyObject *)PyStructSequence_NewType(&addressinfo_desc);
	if (state->addressinfo_type == NULL)
		return -1;

	AddressInfoType = (PyTypeObject *)state->addressinfo_type;

	if (PyModule_AddObjectRef(mod, "AddressInfo", state->addressinfo_type) < 0)
		return -1;

	return 0;
}

py_tnkt_entry_t *
create_keytab_entry(py_tnkt_t *keytab, krb5_keytab_entry *entry)
{
	py_tnkt_entry_t *entry_obj;

	entry_obj = (py_tnkt_entry_t *) PyType_GenericNew(&TruenasKeytabEntryType, NULL, NULL);
	if (entry_obj == NULL)
		return NULL;

	/* Store reference to parent keytab */
	entry_obj->keytab = (py_tnkt_t *)Py_NewRef(keytab);

	/* Copy the keytab entry data */
	entry_obj->entry = *entry;

	/* Initialize datetime object for timestamp */
	entry_obj->timestamp = timestamp_to_datetime((PyObject *)keytab->mod_ref, entry->timestamp);
	if (entry_obj->timestamp == NULL) {
		Py_DECREF(entry_obj);
		return NULL;
	}

	return entry_obj;
}

static PyMethodDef tnkt_entry_methods[] = {
	{NULL, NULL, 0, NULL}
};

PyTypeObject TruenasKeytabEntryType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "truenas_pykrb5.KeytabEntry",
	.tp_doc = "Kerberos keytab entry object with timestamp and vno attributes",
	.tp_basicsize = sizeof(py_tnkt_entry_t),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = py_no_new,
	.tp_dealloc = (destructor) tnkt_entry_dealloc,
	.tp_methods = tnkt_entry_methods,
	.tp_getset = tnkt_entry_getsetters,
};