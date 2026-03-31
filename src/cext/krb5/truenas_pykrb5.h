#ifndef TRUENAS_PYKRB5_H
#define TRUENAS_PYKRB5_H

#define TRUENAS_PYKRB5_MODULE_NAME "truenas_pykrb5"

#define __STRING(x) #x
#define __STRINGSTRING(x) __STRING(x)
#define __LINESTR__ __STRINGSTRING(__LINE__)
#define __location__ __FILE__ ":" __LINESTR__

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#include <Python.h>
#include <pthread.h>
#include <krb5.h>
#include <profile.h>
#include "krb5_err_table.h"
#include "krb5_enctype_table.h"
#include "krb5_principal_table.h"
#include "krb5_addrtype_table.h"
#include "krb5_flags_table.h"

/* Python object wrapping a Kerberos keytab */
typedef struct {
	PyObject_HEAD
	krb5_keytab keytab;
	krb5_context context;
	FILE *tnmemkt; /* in-memory keytab to process bytes */
	pthread_mutex_t ctx_mutex; /* protects krb5_context operations */
	PyObject *mod_ref; /* reference to truenas_pykrb5 module */
	PyObject *pyname; /* keytab file path as PyObject */
} py_tnkt_t;

/* Python object wrapping a Kerberos credential cache */
typedef struct {
	PyObject_HEAD
	krb5_ccache ccache;
	krb5_context context;
	pthread_mutex_t ctx_mutex; /* protects krb5_context operations */
	PyObject *mod_ref; /* reference to truenas_pykrb5 module */
	PyObject *pyname; /* credential cache name as PyObject */
} py_tncc_t;

/* Python object wrapping a Kerberos keytab entry */
typedef struct {
	PyObject_HEAD
	py_tnkt_t *keytab; /* reference to parent keytab object */
	krb5_keytab_entry entry; /* the keytab entry data */
	PyObject *timestamp; /* cached datetime object */
} py_tnkt_entry_t;

/* Cached datetime objects for credential timestamps */
typedef struct {
	PyObject *authtime;
	PyObject *starttime;
	PyObject *endtime;
	PyObject *renew_till;
} krb5_cred_timestamps;

/* Python object wrapping a Kerberos credential */
typedef struct {
	PyObject_HEAD
	py_tncc_t *ccache; /* reference to parent credential cache object */
	krb5_creds creds; /* the credential data */
	krb5_cred_timestamps timestamps; /* cached datetime objects */
} py_tncc_creds_t;

/* Python iterator for Kerberos keytab entries */
typedef struct {
	PyObject_HEAD
	py_tnkt_t *keytab; /* reference to keytab being iterated */
	krb5_kt_cursor cursor; /* keytab cursor for iteration */
} py_tnkt_iter_t;

/* Python iterator for Kerberos credential cache entries */
typedef struct {
	PyObject_HEAD
	py_tncc_t *ccache; /* reference to ccache being iterated */
	krb5_cc_cursor cursor; /* credential cache cursor for iteration */
} py_tncc_iter_t;

/* Error handling structure for KRB5 errors */
typedef struct {
	krb5_error_code code;
	char *context_error;
} tnkrb5_error_t;

/* Module state */
typedef struct {
	PyObject *krb5_error;
	PyObject *krb5_errcode;
	PyObject *krb5_enctype;
	PyObject *krb5_principal_type;
	PyObject *krb5_tktflags;
	PyObject *keyinfo_type;
	PyObject *principalinfo_type;
	PyObject *addressinfo_type;
	PyObject *authdatainfo_type;
	PyObject *datetime_class;
	PyObject *timezone_utc;
} truenas_pykrb5_state;

extern PyObject *TruenasKRB5Error;

/* Type objects defined across translation units */
extern PyTypeObject TruenasKeytabType;
extern PyTypeObject TruenasKeytabEntryType;
extern PyTypeObject TruenasKeytabIterType;
extern PyTypeObject TruenasCcacheType;
extern PyTypeObject TruenasCcacheCredType;
extern PyTypeObject TruenasCcacheIterType;

/*
 * Initialize a krb5 context using an explicit config file path, or the
 * default config if config_file is NULL.  On success, *ctx_out is set and
 * the profile is already embedded in the context (the temporary profile_t is
 * released before returning).
 */
static inline krb5_error_code
init_context_with_config(const char *config_file, krb5_context *ctx_out)
{
	if (config_file == NULL)
		return krb5_init_context(ctx_out);

	const char *files[] = { config_file, NULL };
	profile_t profile = NULL;
	krb5_error_code ret;

	ret = profile_init_flags(files, PROFILE_INIT_ALLOW_MODULE, &profile);
	if (ret)
		return ret;

	ret = krb5_init_context_profile(profile, 0, ctx_out);
	profile_release(profile);
	return ret;
}

/* Prevents direct instantiation of internal types */
PyObject *py_no_new(PyTypeObject *type, PyObject *args, PyObject *kwds);

/* Init functions called directly by module-level constructors */
int tnkt_init(py_tnkt_t *self, PyObject *args, PyObject *kwds);
int tncc_init(py_tncc_t *self, PyObject *args, PyObject *kwds);

/* Credential acquisition (kinit equivalent) */
PyObject *truenas_pykrb5_get_init_creds_keytab(PyObject *mod, PyObject *args, PyObject *kwds);
PyObject *truenas_pykrb5_get_init_creds_password(PyObject *mod, PyObject *args, PyObject *kwds);
extern const char get_init_creds_keytab__doc__[];
extern const char get_init_creds_password__doc__[];

/* Keytab entry functions */
py_tnkt_entry_t *create_keytab_entry(py_tnkt_t *keytab, krb5_keytab_entry *entry);

/* Credential cache credential functions */
py_tncc_creds_t *create_ccache_cred(py_tncc_t *ccache, krb5_creds *creds);


/* Module state functions */
truenas_pykrb5_state *get_module_state(PyObject *mod);

/* Utility functions */
PyObject *timestamp_to_datetime(PyObject *mod, krb5_timestamp timestamp);
PyObject *krb5_address_to_addressinfo(PyObject *mod, krb5_address *address);
PyObject *krb5_keyblock_to_keyinfo(PyObject *mod, krb5_keyblock *keyblock);
PyObject *krb5_authdata_to_authdatainfo(PyObject *mod, krb5_authdata *authdata);

/* Setup functions */
int setup_keyinfo_type(PyObject *mod);
int setup_principalinfo_type(PyObject *mod);
int setup_addressinfo_type(PyObject *mod);
int setup_authdatainfo_type(PyObject *mod);

/* Error handling functions */
PyObject *setup_krb5_exception(void);
int setup_krb5_errcode(PyObject *mod);
int setup_krb5_enctype(PyObject *mod);
int setup_krb5_principal_type(PyObject *mod);
int setup_krb5_tktflags(PyObject *mod);
int tnkrb5_error(krb5_context ctx, krb5_error_code code, tnkrb5_error_t *error);
void tnkrb5_error_free(tnkrb5_error_t *error);
const char *krb5_get_error_name_lookup(krb5_error_code code);
const char *krb5_get_enctype_name_lookup(krb5_enctype enctype);
void _set_exc_from_krb5(tnkrb5_error_t *krb5_err,
			const char *additional_info,
			const char *location);
#define set_exc_from_krb5(err, additional_info) \
	_set_exc_from_krb5(err, additional_info, __location__)

#endif