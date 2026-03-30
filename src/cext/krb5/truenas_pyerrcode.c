#define PY_SSIZE_T_CLEAN
#include "truenas_pykrb5.h"

PyDoc_STRVAR(py_krb5_errcode__doc__,
"KRB5ErrCode(IntEnum)\\n"
"--------------------\\n\\n"
"Kerberos error codes from MIT Kerberos library. These error codes are\\n"
"defined in the MIT Kerberos source and represent various protocol and\\n"
"library errors that can occur during Kerberos operations.\\n\\n"
"Error codes 0-127 are protocol errors from RFC 4120.\\n"
"Error codes 128+ are MIT Kerberos library-specific errors.\\n"
);

int
setup_krb5_errcode(PyObject *mod)
{
	PyObject *enum_module = NULL;
	PyObject *intenum_class = NULL;
	PyObject *errcode_dict = NULL;
	PyObject *errcode_type = NULL;
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

	/* Create dictionary with all error code members */
	errcode_dict = PyDict_New();
	if (errcode_dict == NULL) {
		Py_DECREF(intenum_class);
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(krb5_error_table); i++) {
		member_name = PyUnicode_FromString(krb5_error_table[i].name);
		if (member_name == NULL)
			goto error;

		member_value = PyLong_FromLong(KRB5_ERROR_CODE(krb5_error_table[i].code));
		if (member_value == NULL) {
			Py_DECREF(member_name);
			goto error;
		}

		err = PyDict_SetItem(errcode_dict, member_name, member_value);
		Py_DECREF(member_name);
		Py_DECREF(member_value);
		if (err == -1)
			goto error;
	}

	/* Create KRB5ErrCode IntEnum class */
	PyObject *class_name = PyUnicode_FromString("KRB5ErrCode");
	if (class_name == NULL)
		goto error;

	PyObject *args = PyTuple_Pack(2, class_name, errcode_dict);
	Py_DECREF(class_name);
	if (args == NULL)
		goto error;

	errcode_type = PyObject_Call(intenum_class, args, NULL);
	Py_DECREF(args);

	if (errcode_type == NULL)
		goto error;

	/* Store in module state */
	truenas_pykrb5_state *state = get_module_state(mod);
	if (state == NULL) {
		Py_DECREF(errcode_type);
		goto error;
	}

	state->krb5_errcode = errcode_type;
	Py_INCREF(errcode_type);

	/* Add to module */
	err = PyModule_AddObjectRef(mod, "KRB5ErrCode", errcode_type);
	Py_DECREF(errcode_type);
	if (err == -1)
		goto error;

	Py_DECREF(intenum_class);
	Py_DECREF(errcode_dict);
	return 0;

error:
	Py_DECREF(intenum_class);
	Py_DECREF(errcode_dict);
	return -1;
}