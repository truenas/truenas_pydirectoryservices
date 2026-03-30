#define PY_SSIZE_T_CLEAN
#include "truenas_pykrb5.h"

const char *
krb5_get_enctype_name_lookup(krb5_enctype enctype)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(krb5_enctype_table); i++) {
		if (krb5_enctype_table[i].code == enctype) {
			return krb5_enctype_table[i].name;
		}
	}
	return "UNKNOWN";
}

bool
krb5_get_enctype_deprecated(krb5_enctype enctype)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(krb5_enctype_table); i++) {
		if (krb5_enctype_table[i].code == enctype) {
			return krb5_enctype_table[i].deprecated;
		}
	}
	return false; /* Unknown types are not marked as deprecated */
}

PyDoc_STRVAR(py_krb5_enctype__doc__,
"KRB5EncType(IntEnum)\\n"
"--------------------\\n\\n"
"Kerberos encryption types from MIT Kerberos library. These encryption\\n"
"types represent the cryptographic algorithms supported for Kerberos\\n"
"operations.\\n\\n"
"Only modern, secure encryption types are included:\\n"
"- AES128/256 with HMAC-SHA1 and HMAC-SHA256/384\\n"
"- Camellia 128/256 with CMAC\\n"
"- Special cases: NULL and UNKNOWN\\n"
);

int
setup_krb5_enctype(PyObject *mod)
{
	PyObject *enum_module = NULL;
	PyObject *intenum_class = NULL;
	PyObject *enctype_dict = NULL;
	PyObject *enctype_type = NULL;
	PyObject *member_name = NULL;
	PyObject *member_value = NULL;
	size_t i;
	int err;

	/* Import enum module and get IntEnum class */
	enum_module = PyImport_ImportModule("enum");
	if (enum_module == NULL)
		return -1;

	intenum_class = PyObject_GetAttrString(enum_module, "IntEnum");
	Py_DECREF(enum_module);
	if (intenum_class == NULL)
		return -1;

	/* Create dictionary with all encryption type members */
	enctype_dict = PyDict_New();
	if (enctype_dict == NULL) {
		Py_DECREF(intenum_class);
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(krb5_enctype_table); i++) {
		member_name = PyUnicode_FromString(krb5_enctype_table[i].name);
		if (member_name == NULL)
			goto error;

		member_value = PyLong_FromLong(krb5_enctype_table[i].code);
		if (member_value == NULL) {
			Py_DECREF(member_name);
			goto error;
		}

		err = PyDict_SetItem(enctype_dict, member_name, member_value);
		Py_DECREF(member_name);
		Py_DECREF(member_value);
		if (err == -1)
			goto error;
	}

	/* Create KRB5EncType IntEnum class */
	PyObject *class_name = PyUnicode_FromString("KRB5EncType");
	if (class_name == NULL)
		goto error;

	PyObject *args = PyTuple_Pack(2, class_name, enctype_dict);
	Py_DECREF(class_name);
	if (args == NULL)
		goto error;

	enctype_type = PyObject_Call(intenum_class, args, NULL);
	Py_DECREF(args);

	if (enctype_type == NULL)
		goto error;

	/* Store in module state */
	truenas_pykrb5_state *state = get_module_state(mod);
	if (state == NULL) {
		Py_DECREF(enctype_type);
		goto error;
	}

	state->krb5_enctype = enctype_type;
	Py_INCREF(enctype_type);

	/* Add to module */
	err = PyModule_AddObjectRef(mod, "KRB5EncType", enctype_type);
	Py_DECREF(enctype_type);
	if (err == -1)
		goto error;

	Py_DECREF(intenum_class);
	Py_DECREF(enctype_dict);
	return 0;

error:
	Py_DECREF(intenum_class);
	Py_DECREF(enctype_dict);
	return -1;
}