#define PY_SSIZE_T_CLEAN
#include "truenas_pykrb5.h"

PyObject *
timestamp_to_datetime(PyObject *mod, krb5_timestamp timestamp)
{
	truenas_pykrb5_state *state = get_module_state(mod);
	if (state == NULL || state->datetime_class == NULL || state->timezone_utc == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "datetime not initialized");
		return NULL;
	}

	/* Create datetime object using datetime.fromtimestamp(timestamp, tz=timezone.utc) */
	PyObject *timestamp_obj = PyLong_FromLong((long)timestamp);
	if (timestamp_obj == NULL)
		return NULL;

	PyObject *datetime_obj = PyObject_CallMethod(state->datetime_class, "fromtimestamp", "OO",
						     timestamp_obj, state->timezone_utc);
	Py_DECREF(timestamp_obj);

	return datetime_obj;
}

const char *
krb5_get_addrtype_name_lookup(krb5_addrtype addrtype)
{
	for (int i = 0; krb5_addrtype_table[i].name != NULL; i++) {
		if (krb5_addrtype_table[i].code == addrtype) {
			return krb5_addrtype_table[i].name;
		}
	}
	return "UNKNOWN";
}

PyObject *
krb5_address_to_addressinfo(PyObject *mod, krb5_address *address)
{
	truenas_pykrb5_state *state = get_module_state(mod);
	if (state == NULL || state->addressinfo_type == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "AddressInfo type not initialized");
		return NULL;
	}

	PyObject *addressinfo = PyStructSequence_New((PyTypeObject *)state->addressinfo_type);
	if (addressinfo == NULL)
		return NULL;

	/* Set address type name */
	const char *addrtype_name = krb5_get_addrtype_name_lookup(address->addrtype);
	PyObject *addrtype_str = PyUnicode_FromString(addrtype_name);
	if (addrtype_str == NULL) {
		Py_DECREF(addressinfo);
		return NULL;
	}
	PyStructSequence_SET_ITEM(addressinfo, 0, addrtype_str);

	/* Set address contents */
	PyObject *contents;
	if (address->contents && address->length > 0) {
		contents = PyBytes_FromStringAndSize((const char *)address->contents, address->length);
	} else {
		contents = Py_NewRef(Py_None);
	}
	if (contents == NULL) {
		Py_DECREF(addressinfo);
		return NULL;
	}
	PyStructSequence_SET_ITEM(addressinfo, 1, contents);

	return addressinfo;
}

PyObject *
krb5_keyblock_to_keyinfo(PyObject *mod, krb5_keyblock *keyblock)
{
	truenas_pykrb5_state *state = get_module_state(mod);
	if (state == NULL || state->keyinfo_type == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "KeyInfo type not initialized");
		return NULL;
	}

	PyObject *keyinfo = PyStructSequence_New((PyTypeObject *)state->keyinfo_type);
	if (keyinfo == NULL)
		return NULL;

	/* Get the KRB5EncType enum from module */
	PyObject *module = PyImport_ImportModule("truenas_pykrb5");
	if (module == NULL) {
		Py_DECREF(keyinfo);
		return NULL;
	}

	PyObject *enctype_enum = PyObject_GetAttrString(module, "KRB5EncType");
	Py_DECREF(module);
	if (enctype_enum == NULL) {
		Py_DECREF(keyinfo);
		return NULL;
	}

	/* Create enctype enum instance */
	PyObject *enctype_obj = PyObject_CallFunction(enctype_enum, "i", (int)keyblock->enctype);
	Py_DECREF(enctype_enum);
	if (enctype_obj == NULL) {
		Py_DECREF(keyinfo);
		return NULL;
	}
	PyStructSequence_SET_ITEM(keyinfo, 0, enctype_obj);

	/* Set contents */
	PyObject *contents;
	if (keyblock->contents && keyblock->length > 0) {
		contents = PyBytes_FromStringAndSize((const char *)keyblock->contents, keyblock->length);
	} else {
		contents = Py_NewRef(Py_None);
	}
	if (contents == NULL) {
		Py_DECREF(keyinfo);
		return NULL;
	}
	PyStructSequence_SET_ITEM(keyinfo, 1, contents);

	/* Set deprecated flag */
	PyObject *deprecated = krb5_get_enctype_deprecated(keyblock->enctype) ? Py_True : Py_False;
	PyStructSequence_SET_ITEM(keyinfo, 2, Py_NewRef(deprecated));

	return keyinfo;
}

PyObject *
krb5_authdata_to_authdatainfo(PyObject *mod, krb5_authdata *authdata)
{
	truenas_pykrb5_state *state;
	PyObject *authdatainfo;
	PyObject *ad_type;
	PyObject *contents;

	state = get_module_state(mod);
	if (state == NULL || state->authdatainfo_type == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "AuthDataInfo type not initialized");
		return NULL;
	}

	authdatainfo = PyStructSequence_New((PyTypeObject *)state->authdatainfo_type);
	if (authdatainfo == NULL)
		return NULL;

	/* Set ad_type */
	ad_type = PyLong_FromLong((long)authdata->ad_type);
	if (ad_type == NULL) {
		Py_DECREF(authdatainfo);
		return NULL;
	}
	PyStructSequence_SET_ITEM(authdatainfo, 0, ad_type);

	/* Set contents */
	if (authdata->contents && authdata->length > 0) {
		contents = PyBytes_FromStringAndSize((const char *)authdata->contents, authdata->length);
	} else {
		contents = Py_NewRef(Py_None);
	}
	if (contents == NULL) {
		Py_DECREF(authdatainfo);
		return NULL;
	}
	PyStructSequence_SET_ITEM(authdatainfo, 1, contents);

	return authdatainfo;
}