// SPDX-License-Identifier: LGPL-3.0-or-later

#define _GNU_SOURCE
#define PY_SSIZE_T_CLEAN
#include "truenas_pykrb5.h"
#include <string.h>

#define MAX_CCACHE_NAME_LEN 1024

/*
 * Shared helper: build a Ccache object from a freshly-populated ccache.
 * Takes ownership of ctx and ccache on success.  On failure, the caller
 * must clean up ctx/ccache.
 */
static py_tncc_t *
build_ccache_result(PyObject *mod, krb5_context ctx,
                    krb5_ccache ccache, pthread_mutex_t *mtx)
{
	char name_buf[MAX_CCACHE_NAME_LEN];
	const char *name;

	name = krb5_cc_get_name(ctx, ccache);
	if (name == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
		                "Failed to retrieve credential cache name");
		return NULL;
	}

	strncpy(name_buf, name, sizeof(name_buf) - 1);
	name_buf[sizeof(name_buf) - 1] = '\0';

	py_tncc_t *self = PyObject_New(py_tncc_t, &TruenasCcacheType);
	if (self == NULL)
		return NULL;

	self->context = ctx;
	self->ccache = ccache;
	self->ctx_mutex = *mtx;
	self->mod_ref = Py_NewRef(mod);
	self->pyname = PyUnicode_FromString(name_buf);
	if (self->pyname == NULL) {
		/* dealloc will clean up context/ccache/mutex */
		Py_DECREF(self);
		return NULL;
	}

	return self;
}

/* ── get_init_creds_keytab ─────────────────────────────────────────────── */

const char get_init_creds_keytab__doc__[] =
"get_init_creds_keytab(*, principal, keytab=None, ccache_name=None) -> Ccache\n"
"--\n\n"
"Acquire initial Kerberos credentials using a keytab and store them\n"
"in a credential cache.  Equivalent to kinit -k.\n\n"
"Parameters\n"
"----------\n"
"principal : str -- Kerberos principal name\n"
"keytab : str -- path to keytab file; None uses the default keytab\n"
"ccache_name : str -- credential cache name; None uses the default\n\n"
"Returns\n"
"-------\n"
"Ccache\n\n"
"Raises\n"
"------\n"
"KRB5Error -- authentication or ccache operation failed\n";

PyObject *
truenas_pykrb5_get_init_creds_keytab(PyObject *mod, PyObject *args,
                                     PyObject *kwds)
{
	const char *principal_str = NULL;
	const char *keytab_path = NULL;
	const char *ccache_name = NULL;
	static char *kwlist[] = {"principal", "keytab", "ccache_name", NULL};

	krb5_context ctx = NULL;
	krb5_principal client = NULL;
	krb5_keytab kt = NULL;
	krb5_ccache ccache = NULL;
	krb5_get_init_creds_opt *opts = NULL;
	krb5_creds creds;
	krb5_error_code ret;
	tnkrb5_error_t error;
	pthread_mutex_t mtx;
	int creds_valid = 0;

	memset(&creds, 0, sizeof(creds));

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$szz", kwlist,
	                                 &principal_str, &keytab_path,
	                                 &ccache_name))
		return NULL;

	if (principal_str == NULL) {
		PyErr_SetString(PyExc_TypeError,
		                "get_init_creds_keytab() missing required "
		                "keyword argument: 'principal'");
		return NULL;
	}

	if (pthread_mutex_init(&mtx, NULL) != 0) {
		PyErr_SetString(PyExc_RuntimeError,
		                "Failed to initialize mutex");
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS

	ret = krb5_init_context(&ctx);
	if (ret)
		goto krb5_done;

	ret = krb5_parse_name(ctx, principal_str, &client);
	if (ret)
		goto krb5_done;

	if (keytab_path != NULL)
		ret = krb5_kt_resolve(ctx, keytab_path, &kt);
	else
		ret = krb5_kt_default(ctx, &kt);
	if (ret)
		goto krb5_done;

	if (ccache_name != NULL)
		ret = krb5_cc_resolve(ctx, ccache_name, &ccache);
	else
		ret = krb5_cc_default(ctx, &ccache);
	if (ret)
		goto krb5_done;

	ret = krb5_get_init_creds_opt_alloc(ctx, &opts);
	if (ret)
		goto krb5_done;

	krb5_get_init_creds_opt_set_out_ccache(ctx, opts, ccache);

	ret = krb5_cc_initialize(ctx, ccache, client);
	if (ret)
		goto krb5_done;

	ret = krb5_get_init_creds_keytab(ctx, &creds, client, kt,
	                                 0, NULL, opts);
	if (ret == 0)
		creds_valid = 1;

krb5_done:
	if (ret)
		tnkrb5_error(ctx, ret, &error);

	if (creds_valid)
		krb5_free_cred_contents(ctx, &creds);
	if (opts)
		krb5_get_init_creds_opt_free(ctx, opts);
	if (client)
		krb5_free_principal(ctx, client);
	if (kt)
		krb5_kt_close(ctx, kt);

	Py_END_ALLOW_THREADS

	if (ret) {
		set_exc_from_krb5(&error,
		                  "Failed to acquire credentials from keytab");
		tnkrb5_error_free(&error);
		if (ccache)
			krb5_cc_close(ctx, ccache);
		if (ctx)
			krb5_free_context(ctx);
		pthread_mutex_destroy(&mtx);
		return NULL;
	}

	py_tncc_t *result = build_ccache_result(mod, ctx, ccache, &mtx);
	if (result == NULL) {
		krb5_cc_close(ctx, ccache);
		krb5_free_context(ctx);
		pthread_mutex_destroy(&mtx);
		return NULL;
	}

	return (PyObject *)result;
}

/* ── get_init_creds_password ───────────────────────────────────────────── */

const char get_init_creds_password__doc__[] =
"get_init_creds_password(*, principal, password, ccache_name=None) -> Ccache\n"
"--\n\n"
"Acquire initial Kerberos credentials using a password and store them\n"
"in a credential cache.  Equivalent to kinit with a password.\n\n"
"Parameters\n"
"----------\n"
"principal : str -- Kerberos principal name\n"
"password : str -- password for the principal\n"
"ccache_name : str -- credential cache name; None uses the default\n\n"
"Returns\n"
"-------\n"
"Ccache\n\n"
"Raises\n"
"------\n"
"KRB5Error -- authentication or ccache operation failed\n";

PyObject *
truenas_pykrb5_get_init_creds_password(PyObject *mod, PyObject *args,
                                       PyObject *kwds)
{
	const char *principal_str = NULL;
	const char *password = NULL;
	const char *ccache_name = NULL;
	static char *kwlist[] = {"principal", "password", "ccache_name", NULL};

	krb5_context ctx = NULL;
	krb5_principal client = NULL;
	krb5_ccache ccache = NULL;
	krb5_get_init_creds_opt *opts = NULL;
	krb5_creds creds;
	krb5_error_code ret;
	tnkrb5_error_t error;
	pthread_mutex_t mtx;
	int creds_valid = 0;

	memset(&creds, 0, sizeof(creds));

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$szz", kwlist,
	                                 &principal_str, &password,
	                                 &ccache_name))
		return NULL;

	if (principal_str == NULL || password == NULL) {
		PyErr_SetString(PyExc_TypeError,
		                "get_init_creds_password() missing required "
		                "keyword arguments: 'principal' and 'password'");
		return NULL;
	}

	if (pthread_mutex_init(&mtx, NULL) != 0) {
		PyErr_SetString(PyExc_RuntimeError,
		                "Failed to initialize mutex");
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS

	ret = krb5_init_context(&ctx);
	if (ret)
		goto krb5_done;

	ret = krb5_parse_name(ctx, principal_str, &client);
	if (ret)
		goto krb5_done;

	if (ccache_name != NULL)
		ret = krb5_cc_resolve(ctx, ccache_name, &ccache);
	else
		ret = krb5_cc_default(ctx, &ccache);
	if (ret)
		goto krb5_done;

	ret = krb5_get_init_creds_opt_alloc(ctx, &opts);
	if (ret)
		goto krb5_done;

	krb5_get_init_creds_opt_set_out_ccache(ctx, opts, ccache);

	ret = krb5_cc_initialize(ctx, ccache, client);
	if (ret)
		goto krb5_done;

	ret = krb5_get_init_creds_password(ctx, &creds, client, password,
	                                   NULL, NULL, 0, NULL, opts);
	if (ret == 0)
		creds_valid = 1;

krb5_done:
	if (ret)
		tnkrb5_error(ctx, ret, &error);

	if (creds_valid)
		krb5_free_cred_contents(ctx, &creds);
	if (opts)
		krb5_get_init_creds_opt_free(ctx, opts);
	if (client)
		krb5_free_principal(ctx, client);

	Py_END_ALLOW_THREADS

	if (ret) {
		set_exc_from_krb5(&error,
		                  "Failed to acquire credentials with password");
		tnkrb5_error_free(&error);
		if (ccache)
			krb5_cc_close(ctx, ccache);
		if (ctx)
			krb5_free_context(ctx);
		pthread_mutex_destroy(&mtx);
		return NULL;
	}

	py_tncc_t *result = build_ccache_result(mod, ctx, ccache, &mtx);
	if (result == NULL) {
		krb5_cc_close(ctx, ccache);
		krb5_free_context(ctx);
		pthread_mutex_destroy(&mtx);
		return NULL;
	}

	return (PyObject *)result;
}
