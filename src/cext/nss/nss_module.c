// SPDX-License-Identifier: LGPL-3.0-or-later

#include <Python.h>
#include "common/includes.h"
#include "nss_module.h"

/* Architecture-specific library directory (matches ctypes implementation) */
#define NSS_MODULES_DIR "/usr/lib/x86_64-linux-gnu"

#define FILES_NSS_PATH NSS_MODULES_DIR "/libnss_files.so.2"
#define SSS_NSS_PATH NSS_MODULES_DIR "/libnss_sss.so.2"
#define WINBIND_NSS_PATH NSS_MODULES_DIR "/libnss_winbind.so.2"

typedef struct {
	const char *mod_name; /* lowercase module name used in symbol: "files" */
	const char *py_name; /* uppercase Python name: "FILES" */
	const char *path; /* path to .so */
	void *dlhandle; /* NULL until first use */
	pthread_mutex_t iter_lock; /* held during iteration for non-thread-safe backends */
	bool needs_iter_lock; /* true if backend iteration is not thread-safe */
} nss_module_entry_t;

static nss_module_entry_t nss_modules[NSS_MOD_COUNT] = {
	[NSS_MOD_FILES] = {
		"files", "FILES", FILES_NSS_PATH, NULL,
		PTHREAD_MUTEX_INITIALIZER, true
	},
	[NSS_MOD_SSS] = {
		"sss", "SSS", SSS_NSS_PATH, NULL,
		PTHREAD_MUTEX_INITIALIZER, false
	},
	[NSS_MOD_WINBIND] = {
		"winbind", "WINBIND", WINBIND_NSS_PATH, NULL,
		PTHREAD_MUTEX_INITIALIZER, false
	},
};

static const char *nss_op_suffix[NSS_OP_COUNT] = {
	[NSS_OP_GETPWNAM_R] = "getpwnam_r",
	[NSS_OP_GETPWUID_R] = "getpwuid_r",
	[NSS_OP_SETPWENT] = "setpwent",
	[NSS_OP_ENDPWENT] = "endpwent",
	[NSS_OP_GETPWENT_R] = "getpwent_r",
	[NSS_OP_GETGRNAM_R] = "getgrnam_r",
	[NSS_OP_GETGRGID_R] = "getgrgid_r",
	[NSS_OP_SETGRENT] = "setgrent",
	[NSS_OP_ENDGRENT] = "endgrent",
	[NSS_OP_GETGRENT_R] = "getgrent_r",
};

int
parse_module_name(const char *name, int *mod_idx_out)
{
	if (strcmp(name, "ALL") == 0) {
		*mod_idx_out = NSS_MOD_ALL;
		return 0;
	}
	for (int i = 0; i < NSS_MOD_COUNT; i++) {
		if (strcmp(name, nss_modules[i].py_name) == 0) {
			*mod_idx_out = i;
			return 0;
		}
	}
	PyErr_Format(PyExc_ValueError,
	             "Unknown NSS module: '%s'. "
	             "Valid values: FILES, SSS, WINBIND, ALL", name);
	return -1;
}

const char *
mod_idx_to_name(int mod_idx)
{
	if (mod_idx == NSS_MOD_ALL)
		return "ALL";
	if (mod_idx < 0 || mod_idx >= NSS_MOD_COUNT)
		return "UNKNOWN";
	return nss_modules[mod_idx].py_name;
}

bool
get_nss_fn(int mod_idx, nss_op_t op, nss_fn_t *out)
{
	nss_module_entry_t *ent;
	char sym[256];
	void *fn;

	if (mod_idx < 0 || mod_idx >= NSS_MOD_COUNT) {
		PyErr_SetString(PyExc_ValueError, "Invalid NSS module index");
		return false;
	}

	if (op < 0 || op >= NSS_OP_COUNT) {
		PyErr_SetString(PyExc_ValueError, "Invalid NSS operation");
		return false;
	}

	ent = &nss_modules[mod_idx];

	/* Lazy-open the shared library */
	if (ent->dlhandle == NULL) {
		ent->dlhandle = dlopen(ent->path, RTLD_NOW | RTLD_LOCAL);
		if (ent->dlhandle == NULL) {
			PyErr_Format(PyExc_OSError,
			             "Failed to load NSS module '%s' from '%s': %s",
			             ent->py_name, ent->path, dlerror());
			return false;
		}
	}

	/* Build _nss_{module}_{op} symbol name */
	if ((size_t)snprintf(sym, sizeof(sym), "_nss_%s_%s",
	                     ent->mod_name, nss_op_suffix[op]) >= sizeof(sym)) {
		PyErr_SetString(PyExc_OverflowError, "NSS symbol name too long");
		return false;
	}

	fn = dlsym(ent->dlhandle, sym);
	if (fn == NULL) {
		PyErr_Format(PyExc_AttributeError,
		             "NSS function '%s' not found in '%s': %s",
		             sym, ent->path, dlerror());
		return false;
	}

	switch (op) {
	case NSS_OP_GETPWNAM_R: out->getpwnam_r = fn; break;
	case NSS_OP_GETPWUID_R: out->getpwuid_r = fn; break;
	case NSS_OP_SETPWENT: out->setpwent = fn; break;
	case NSS_OP_ENDPWENT: out->endpwent = fn; break;
	case NSS_OP_GETPWENT_R: out->getpwent_r = fn; break;
	case NSS_OP_GETGRNAM_R: out->getgrnam_r = fn; break;
	case NSS_OP_GETGRGID_R: out->getgrgid_r = fn; break;
	case NSS_OP_SETGRENT: out->setgrent = fn; break;
	case NSS_OP_ENDGRENT: out->endgrent = fn; break;
	case NSS_OP_GETGRENT_R: out->getgrent_r = fn; break;
	case NSS_OP_COUNT: break;
	}

	return true;
}

void
nss_iter_lock(int mod_idx)
{
	nss_module_entry_t *ent;

	if (mod_idx < 0 || mod_idx >= NSS_MOD_COUNT)
		return;

	ent = &nss_modules[mod_idx];
	if (!ent->needs_iter_lock)
		return;

	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&ent->iter_lock);
	Py_END_ALLOW_THREADS
}

void
nss_iter_unlock(int mod_idx)
{
	nss_module_entry_t *ent;

	if (mod_idx < 0 || mod_idx >= NSS_MOD_COUNT)
		return;

	ent = &nss_modules[mod_idx];
	if (!ent->needs_iter_lock)
		return;

	pthread_mutex_unlock(&ent->iter_lock);
}
