#define PY_SSIZE_T_CLEAN
#include "truenas_pykrb5.h"

PyObject *
py_no_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	PyErr_Format(PyExc_TypeError,
	             "%.100s cannot be instantiated directly",
	             type->tp_name);
	return NULL;
}

static struct {
	const char *name;
	PyTypeObject *type;
} type_exports[] = {
	{ "Keytab", &TruenasKeytabType },
	{ "KeytabEntry", &TruenasKeytabEntryType },
	{ "KeytabIter", &TruenasKeytabIterType },
	{ "Ccache", &TruenasCcacheType },
	{ "CcacheCred", &TruenasCcacheCredType },
	{ "CcacheIter", &TruenasCcacheIterType },
	{ NULL, NULL }
};

PyDoc_STRVAR(truenas_pykrb5_get_keytab__doc__,
"get_keytab(*, filename=None, data=None) -> truenas_pykrb5.Keytab\n"
"------------------------------------------------------------\n\n"
"Create a new Keytab instance for reading Kerberos keytab entries.\n\n"
"Parameters\n"
"----------\n"
"filename: str, optional\n"
"    Path to keytab file to open.\n\n"
"data: bytes, optional\n"
"    Keytab data as bytes to process in memory.\n\n"
"If neither filename nor data is provided, opens the default system keytab.\n"
"Only one of filename or data may be specified.\n\n"
"Returns\n"
"-------\n"
"truenas_pykrb5.Keytab\n"
"    A Keytab object that can be iterated to access keytab entries.\n"
);

static PyObject *
truenas_pykrb5_get_keytab(PyObject *mod, PyObject *args, PyObject *kwds)
{
	py_tnkt_t *keytab = PyObject_New(py_tnkt_t, &TruenasKeytabType);
	if (keytab == NULL)
		return NULL;

	if (tnkt_init(keytab, args, kwds) < 0) {
		Py_DECREF(keytab);
		return NULL;
	}

	keytab->mod_ref = Py_NewRef(mod);
	return (PyObject *)keytab;
}

PyDoc_STRVAR(truenas_pykrb5_get_ccache__doc__,
"get_ccache(*, ccache_name=None) -> truenas_pykrb5.Ccache\n"
"------------------------------------------------------\n\n"
"Create a new Ccache instance for accessing Kerberos credential cache.\n\n"
"Parameters\n"
"----------\n"
"ccache_name: str, optional\n"
"    Name of credential cache to open.\n\n"
"If ccache_name is not provided, opens the default credential cache.\n\n"
"Returns\n"
"-------\n"
"truenas_pykrb5.Ccache\n"
"    A Ccache object for accessing credential cache information.\n"
);

static PyObject *
truenas_pykrb5_get_ccache(PyObject *mod, PyObject *args, PyObject *kwds)
{
	py_tncc_t *ccache = PyObject_New(py_tncc_t, &TruenasCcacheType);
	if (ccache == NULL)
		return NULL;

	if (tncc_init(ccache, args, kwds) < 0) {
		Py_DECREF(ccache);
		return NULL;
	}

	ccache->mod_ref = Py_NewRef(mod);
	return (PyObject *)ccache;
}

static PyMethodDef truenas_pykrb5_methods[] = {
	{
		.ml_name = "get_keytab",
		.ml_meth = (PyCFunction)truenas_pykrb5_get_keytab,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = truenas_pykrb5_get_keytab__doc__
	},
	{
		.ml_name = "get_ccache",
		.ml_meth = (PyCFunction)truenas_pykrb5_get_ccache,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = truenas_pykrb5_get_ccache__doc__
	},
	{
		.ml_name = "get_init_creds_keytab",
		.ml_meth = (PyCFunction)truenas_pykrb5_get_init_creds_keytab,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = get_init_creds_keytab__doc__
	},
	{
		.ml_name = "get_init_creds_password",
		.ml_meth = (PyCFunction)truenas_pykrb5_get_init_creds_password,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = get_init_creds_password__doc__
	},
	{NULL, NULL, 0, NULL}
};

static int
truenas_pykrb5_traverse(PyObject *mod, visitproc visit, void *arg)
{
	truenas_pykrb5_state *state = get_module_state(mod);
	if (state) {
		Py_VISIT(state->krb5_error);
		Py_VISIT(state->krb5_errcode);
		Py_VISIT(state->krb5_enctype);
		Py_VISIT(state->krb5_principal_type);
		Py_VISIT(state->krb5_tktflags);
		Py_VISIT(state->keyinfo_type);
		Py_VISIT(state->principalinfo_type);
		Py_VISIT(state->addressinfo_type);
		Py_VISIT(state->authdatainfo_type);
		Py_VISIT(state->datetime_class);
		Py_VISIT(state->timezone_utc);
	}
	return 0;
}

static int
truenas_pykrb5_clear(PyObject *mod)
{
	truenas_pykrb5_state *state = get_module_state(mod);
	if (state) {
		Py_CLEAR(state->krb5_error);
		Py_CLEAR(state->krb5_errcode);
		Py_CLEAR(state->krb5_enctype);
		Py_CLEAR(state->krb5_principal_type);
		Py_CLEAR(state->krb5_tktflags);
		Py_CLEAR(state->keyinfo_type);
		Py_CLEAR(state->principalinfo_type);
		Py_CLEAR(state->addressinfo_type);
		Py_CLEAR(state->authdatainfo_type);
		Py_CLEAR(state->datetime_class);
		Py_CLEAR(state->timezone_utc);
	}
	return 0;
}

static struct PyModuleDef truenas_pykrb5_module = {
	PyModuleDef_HEAD_INIT,
	"truenas_pykrb5",
	"TrueNAS Kerberos library Python bindings",
	sizeof(truenas_pykrb5_state),
	truenas_pykrb5_methods,
	NULL,
	truenas_pykrb5_traverse,
	truenas_pykrb5_clear,
	NULL
};

truenas_pykrb5_state *
get_module_state(PyObject *mod)
{
	return (truenas_pykrb5_state *)PyModule_GetState(mod);
}

PyMODINIT_FUNC PyInit_truenas_pykrb5(void)
{
	PyObject *module;
	truenas_pykrb5_state *state;

	if (PyType_Ready(&TruenasKeytabType) < 0)
		return NULL;

	if (PyType_Ready(&TruenasKeytabEntryType) < 0)
		return NULL;

	if (PyType_Ready(&TruenasKeytabIterType) < 0)
		return NULL;

	if (PyType_Ready(&TruenasCcacheType) < 0)
		return NULL;

	if (PyType_Ready(&TruenasCcacheIterType) < 0)
		return NULL;

	if (PyType_Ready(&TruenasCcacheCredType) < 0)
		return NULL;

	module = PyModule_Create(&truenas_pykrb5_module);
	if (module == NULL)
		return NULL;

	/* Export type objects to module dict */
	for (int i = 0; type_exports[i].name != NULL; i++) {
		if (PyModule_AddObjectRef(module, type_exports[i].name,
		                          (PyObject *)type_exports[i].type) < 0) {
			Py_DECREF(module);
			return NULL;
		}
	}

	state = get_module_state(module);
	if (state == NULL) {
		Py_DECREF(module);
		return NULL;
	}

	/* Setup KRB5 exception */
	state->krb5_error = setup_krb5_exception();
	if (state->krb5_error == NULL) {
		Py_DECREF(module);
		return NULL;
	}
	TruenasKRB5Error = state->krb5_error;

	if (PyModule_AddObjectRef(module, "KRB5Error", state->krb5_error) < 0) {
		Py_DECREF(module);
		return NULL;
	}

	/* Setup KRB5 error code enum */
	if (setup_krb5_errcode(module) < 0) {
		Py_DECREF(module);
		return NULL;
	}

	/* Setup KRB5 encryption type enum */
	if (setup_krb5_enctype(module) < 0) {
		Py_DECREF(module);
		return NULL;
	}

	/* Setup KRB5 principal type enum */
	if (setup_krb5_principal_type(module) < 0) {
		Py_DECREF(module);
		return NULL;
	}

	/* Setup KRB5 ticket flags enum */
	if (setup_krb5_tktflags(module) < 0) {
		Py_DECREF(module);
		return NULL;
	}

	/* Setup KeyInfo struct sequence type */
	if (setup_keyinfo_type(module) < 0) {
		Py_DECREF(module);
		return NULL;
	}

	/* Setup PrincipalInfo struct sequence type */
	if (setup_principalinfo_type(module) < 0) {
		Py_DECREF(module);
		return NULL;
	}

	/* Setup AddressInfo struct sequence type */
	if (setup_addressinfo_type(module) < 0) {
		Py_DECREF(module);
		return NULL;
	}

	/* Setup AuthDataInfo struct sequence type */
	if (setup_authdatainfo_type(module) < 0) {
		Py_DECREF(module);
		return NULL;
	}

	/* Setup datetime and timezone references */
	PyObject *datetime_module = PyImport_ImportModule("datetime");
	if (datetime_module == NULL) {
		Py_DECREF(module);
		return NULL;
	}

	state->datetime_class = PyObject_GetAttrString(datetime_module, "datetime");
	if (state->datetime_class == NULL) {
		Py_DECREF(datetime_module);
		Py_DECREF(module);
		return NULL;
	}

	PyObject *timezone_class = PyObject_GetAttrString(datetime_module, "timezone");
	if (timezone_class == NULL) {
		Py_DECREF(datetime_module);
		Py_DECREF(module);
		return NULL;
	}

	state->timezone_utc = PyObject_GetAttrString(timezone_class, "utc");
	if (state->timezone_utc == NULL) {
		Py_DECREF(timezone_class);
		Py_DECREF(datetime_module);
		Py_DECREF(module);
		return NULL;
	}

	Py_DECREF(timezone_class);
	Py_DECREF(datetime_module);

	return module;
}