#define PY_SSIZE_T_CLEAN
#include "truenas_pykrb5.h"

PyDoc_STRVAR(py_krb5_tktflags__doc__,
"KRB5TktFlags(IntFlag)\\n"
"---------------------\\n\\n"
"Kerberos ticket flags from MIT Kerberos library. These flags represent\\n"
"various properties and capabilities of Kerberos tickets.\\n\\n"
"Flags include:\\n"
"- FORWARDABLE: Ticket can be forwarded\\n"
"- FORWARDED: Ticket has been forwarded\\n"
"- PROXIABLE: Ticket can be proxied\\n"
"- PROXY: Ticket is a proxy\\n"
"- MAY_POSTDATE: Ticket may be postdated\\n"
"- POSTDATED: Ticket has been postdated\\n"
"- INVALID: Ticket is invalid\\n"
"- RENEWABLE: Ticket is renewable\\n"
"- INITIAL: Initial ticket from KDC\\n"
"- PRE_AUTH: Pre-authentication was used\\n"
"- HW_AUTH: Hardware authentication was used\\n"
"- TRANSIT_POLICY_CHECKED: Transit policy has been checked\\n"
"- OK_AS_DELEGATE: Ticket allows delegation\\n"
"- ENC_PA_REP: Encrypted PA-REP\\n"
"- ANONYMOUS: Anonymous ticket\\n"
);

int
setup_krb5_tktflags(PyObject *mod)
{
	PyObject *enum_module = NULL;
	PyObject *intflag_class = NULL;
	PyObject *tktflags_dict = NULL;
	PyObject *tktflags_type = NULL;
	PyObject *member_name = NULL;
	PyObject *member_value = NULL;
	size_t i;
	int err;

	/* Import enum module and get IntFlag class */
	enum_module = PyImport_ImportModule("enum");
	if (enum_module == NULL)
		return -1;

	intflag_class = PyObject_GetAttrString(enum_module, "IntFlag");
	Py_DECREF(enum_module);
	if (intflag_class == NULL)
		return -1;

	/* Create dictionary with all ticket flag members */
	tktflags_dict = PyDict_New();
	if (tktflags_dict == NULL) {
		Py_DECREF(intflag_class);
		return -1;
	}

	for (i = 0; krb5_flags_table[i].name != NULL; i++) {
		member_name = PyUnicode_FromString(krb5_flags_table[i].name);
		if (member_name == NULL)
			goto error;

		member_value = PyLong_FromLong((long)krb5_flags_table[i].flag);
		if (member_value == NULL) {
			Py_DECREF(member_name);
			goto error;
		}

		err = PyDict_SetItem(tktflags_dict, member_name, member_value);
		Py_DECREF(member_name);
		Py_DECREF(member_value);
		if (err == -1)
			goto error;
	}

	/* Create KRB5TktFlags IntFlag class */
	PyObject *class_name = PyUnicode_FromString("KRB5TktFlags");
	if (class_name == NULL)
		goto error;

	PyObject *args = PyTuple_Pack(2, class_name, tktflags_dict);
	Py_DECREF(class_name);
	if (args == NULL)
		goto error;

	tktflags_type = PyObject_Call(intflag_class, args, NULL);
	Py_DECREF(args);

	if (tktflags_type == NULL)
		goto error;

	/* Store in module state */
	truenas_pykrb5_state *state = get_module_state(mod);
	if (state == NULL) {
		Py_DECREF(tktflags_type);
		goto error;
	}

	state->krb5_tktflags = tktflags_type;
	Py_INCREF(tktflags_type);

	/* Add to module */
	err = PyModule_AddObjectRef(mod, "KRB5TktFlags", tktflags_type);
	Py_DECREF(tktflags_type);
	if (err == -1)
		goto error;

	Py_DECREF(intflag_class);
	Py_DECREF(tktflags_dict);
	return 0;

error:
	Py_DECREF(intflag_class);
	Py_DECREF(tktflags_dict);
	return -1;
}