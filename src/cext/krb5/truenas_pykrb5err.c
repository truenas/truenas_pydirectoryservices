#define PY_SSIZE_T_CLEAN
#include <string.h>
#include "truenas_pykrb5.h"

static PyObject *PyExc_KRB5Error = NULL;

PyDoc_STRVAR(py_krb5_error__doc__,
"KRB5Error(exception)\n"
"--------------------\n\n"
"Python wrapper around Kerberos library errors. A krb5 error will have\n"
"the following information:\n\n"
"krb5 error code:\n"
"    Numeric error code returned by krb5 library functions.\n\n"
"krb5 error message:\n"
"    Human-readable error message from krb5_get_error_message().\n\n"
"krb5 error name:\n"
"    Symbolic name of the error from krb5_get_error_name().\n\n"
"attributes:\n"
"-----------\n"
"code: int\n"
"    krb5 error code\n"
"context_error: str\n"
"    human-readable error description from krb5 context\n"
"name: str\n"
"    symbolic name of the krb5 error code\n"
"location: str\n"
"    line of file in uncompiled source of this module\n"
);

PyObject *setup_krb5_exception(void)
{
	PyObject *dict = NULL;

	dict = Py_BuildValue("{s:i,s:s,s:s,s:s}",
			     "code", 0,
			     "context_error", "",
			     "name", "",
			     "location", "");
	if (dict == NULL)
		return NULL;

	PyExc_KRB5Error = PyErr_NewExceptionWithDoc(TRUENAS_PYKRB5_MODULE_NAME ".KRB5Error",
						    py_krb5_error__doc__,
						    PyExc_RuntimeError,
						    dict);

	Py_DECREF(dict);
	return PyExc_KRB5Error;
}

PyObject *TruenasKRB5Error = NULL;

int
tnkrb5_error(krb5_context ctx, krb5_error_code code, tnkrb5_error_t *error)
{
	const char *error_msg;
	size_t msg_len;

	if (!error)
		return -1;

	*error = (tnkrb5_error_t){
		.code = code,
		.context_error = NULL
	};

	if (code == 0)
		return 0;

	error_msg = krb5_get_error_message(ctx, code);
	if (error_msg) {
		msg_len = strlen(error_msg) + 1;
		error->context_error = PyMem_RawMalloc(msg_len);
		if (!error->context_error) {
			krb5_free_error_message(ctx, error_msg);
			return -1;
		}
		strlcpy(error->context_error, error_msg, msg_len);
		krb5_free_error_message(ctx, error_msg);
	}

	return 0;
}

void
tnkrb5_error_free(tnkrb5_error_t *error)
{
	if (!error)
		return;

	PyMem_RawFree(error->context_error);
	*error = (tnkrb5_error_t){
		.code = 0,
		.context_error = NULL
	};
}


const char *
krb5_get_error_name_lookup(krb5_error_code code)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(krb5_error_table); i++) {
		if (krb5_error_table[i].code == code) {
			return krb5_error_table[i].name;
		}
	}
	return "UNKNOWN";
}

void
_set_exc_from_krb5(tnkrb5_error_t *krb5_err, const char *additional_info, const char *location)
{
	PyObject *v = NULL;
	PyObject *args = NULL;
	PyObject *attrs = NULL;
	PyObject *errstr = NULL;
	int err;

	if (!TruenasKRB5Error) {
		PyErr_SetString(PyExc_RuntimeError, "KRB5Error not initialized");
		return;
	}

	if (additional_info && krb5_err->context_error) {
		errstr = PyUnicode_FromFormat("[KRB5:%d]: %s - %s",
					      krb5_err->code,
					      additional_info,
					      krb5_err->context_error);
	} else if (krb5_err->context_error) {
		errstr = PyUnicode_FromFormat("[KRB5:%d]: %s",
					      krb5_err->code,
					      krb5_err->context_error);
	} else {
		errstr = PyUnicode_FromFormat("[KRB5:%d]: %s",
					      krb5_err->code,
					      additional_info ? additional_info : "Unknown error");
	}

	if (errstr == NULL) {
		goto simple_err;
	}

	args = Py_BuildValue("(N)", errstr);
	if (args == NULL) {
		Py_DECREF(errstr);
		goto simple_err;
	}

	v = PyObject_Call(TruenasKRB5Error, args, NULL);
	if (v == NULL) {
		Py_CLEAR(args);
		return;
	}

	attrs = Py_BuildValue("(issO)",
			      krb5_err->code,
			      krb5_err->context_error ? krb5_err->context_error : "",
			      krb5_get_error_name_lookup(krb5_err->code),
			      location ? PyUnicode_FromString(location) : PyUnicode_FromString(""));

	if (attrs == NULL) {
		Py_XDECREF(v);
		goto simple_err;
	}

	err = PyObject_SetAttrString(v, "code", PyTuple_GetItem(attrs, 0));
	if (err == -1) {
		Py_CLEAR(args);
		Py_CLEAR(v);
		return;
	}

	err = PyObject_SetAttrString(v, "context_error", PyTuple_GetItem(attrs, 1));
	if (err == -1) {
		Py_CLEAR(args);
		Py_CLEAR(v);
		return;
	}

	err = PyObject_SetAttrString(v, "name", PyTuple_GetItem(attrs, 2));
	if (err == -1) {
		Py_CLEAR(args);
		Py_CLEAR(v);
		return;
	}

	err = PyObject_SetAttrString(v, "location", PyTuple_GetItem(attrs, 3));
	if (err == -1) {
		Py_CLEAR(args);
		Py_CLEAR(v);
		return;
	}

	PyErr_SetObject(TruenasKRB5Error, v);
	Py_DECREF(args);
	Py_DECREF(attrs);
	Py_DECREF(v);
	return;

simple_err:
	PyErr_SetString(TruenasKRB5Error, additional_info ? additional_info : "Unknown KRB5 error");
}