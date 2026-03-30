#define PY_SSIZE_T_CLEAN
#include "truenas_pykrb5.h"

const char *
krb5_get_principal_type_name_lookup(krb5_int32 type)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(krb5_principal_type_table); i++) {
		if (krb5_principal_type_table[i].code == type) {
			return krb5_principal_type_table[i].name;
		}
	}
	return "UNKNOWN";
}

PyDoc_STRVAR(py_krb5_principal_type__doc__,
"KRB5PrincipalType(IntEnum)\\n"
"-----------------------------\\n\\n"
"Kerberos principal name types from MIT Kerberos library. These types\\n"
"specify what kind of principal name is being represented.\\n\\n"
"Common types:\\n"
"- KRB5_NT_PRINCIPAL: Regular user principals\\n"
"- KRB5_NT_SRV_HST: Service principals with hostname\\n"
"- KRB5_NT_ENTERPRISE_PRINCIPAL: Windows UPN format\\n"
);

int
setup_krb5_principal_type(PyObject *mod)
{
	PyObject *enum_module = NULL;
	PyObject *intenum_class = NULL;
	PyObject *principal_type_dict = NULL;
	PyObject *principal_type_type = NULL;
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

	/* Create dictionary with all principal type members */
	principal_type_dict = PyDict_New();
	if (principal_type_dict == NULL) {
		Py_DECREF(intenum_class);
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(krb5_principal_type_table); i++) {
		member_name = PyUnicode_FromString(krb5_principal_type_table[i].name);
		if (member_name == NULL)
			goto error;

		member_value = PyLong_FromLong(krb5_principal_type_table[i].code);
		if (member_value == NULL) {
			Py_DECREF(member_name);
			goto error;
		}

		err = PyDict_SetItem(principal_type_dict, member_name, member_value);
		Py_DECREF(member_name);
		Py_DECREF(member_value);
		if (err == -1)
			goto error;
	}

	/* Create KRB5PrincipalType IntEnum class */
	PyObject *class_name = PyUnicode_FromString("KRB5PrincipalType");
	if (class_name == NULL)
		goto error;

	PyObject *args = PyTuple_Pack(2, class_name, principal_type_dict);
	Py_DECREF(class_name);
	if (args == NULL)
		goto error;

	principal_type_type = PyObject_Call(intenum_class, args, NULL);
	Py_DECREF(args);

	if (principal_type_type == NULL)
		goto error;

	/* Store in module state */
	truenas_pykrb5_state *state = get_module_state(mod);
	if (state == NULL) {
		Py_DECREF(principal_type_type);
		goto error;
	}

	state->krb5_principal_type = principal_type_type;
	Py_INCREF(principal_type_type);

	/* Add to module */
	err = PyModule_AddObjectRef(mod, "KRB5PrincipalType", principal_type_type);
	Py_DECREF(principal_type_type);
	if (err == -1)
		goto error;

	Py_DECREF(intenum_class);
	Py_DECREF(principal_type_dict);
	return 0;

error:
	Py_DECREF(intenum_class);
	Py_DECREF(principal_type_dict);
	return -1;
}