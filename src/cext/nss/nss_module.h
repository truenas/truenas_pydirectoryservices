// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef NSS_MODULE_H
#define NSS_MODULE_H

#include "common/includes.h"

/* Module indices */
#define NSS_MOD_ALL (-1)
#define NSS_MOD_FILES 0
#define NSS_MOD_SSS 1
#define NSS_MOD_WINBIND 2
#define NSS_MOD_COUNT 3

/* NSS operation identifiers */
typedef enum {
	NSS_OP_GETPWNAM_R,
	NSS_OP_GETPWUID_R,
	NSS_OP_SETPWENT,
	NSS_OP_ENDPWENT,
	NSS_OP_GETPWENT_R,
	NSS_OP_GETGRNAM_R,
	NSS_OP_GETGRGID_R,
	NSS_OP_SETGRENT,
	NSS_OP_ENDGRENT,
	NSS_OP_GETGRENT_R,
	NSS_OP_COUNT
} nss_op_t;

/* Typed function pointer union — access the member matching the requested op */
typedef union {
	enum nss_status (*getpwnam_r)(const char *, struct passwd *, char *, size_t, int *);
	enum nss_status (*getpwuid_r)(uid_t, struct passwd *, char *, size_t, int *);
	enum nss_status (*setpwent)(int);
	enum nss_status (*endpwent)(void);
	enum nss_status (*getpwent_r)(struct passwd *, char *, size_t, int *);
	enum nss_status (*getgrnam_r)(const char *, struct group *, char *, size_t, int *);
	enum nss_status (*getgrgid_r)(gid_t, struct group *, char *, size_t, int *);
	enum nss_status (*setgrent)(int);
	enum nss_status (*endgrent)(void);
	enum nss_status (*getgrent_r)(struct group *, char *, size_t, int *);
} nss_fn_t;

/*
 * Parse a module name string ("FILES", "SSS", "WINBIND", "ALL") into
 * a module index.  Sets a Python exception and returns -1 on error.
 */
int parse_module_name(const char *name, int *mod_idx_out);

/* Return the Python-level name for a module index (e.g. "FILES"). */
const char *mod_idx_to_name(int mod_idx);

/*
 * Resolve the NSS function for the given module and operation, opening
 * the shared library on first use.  Populates *out with a typed function
 * pointer on success.
 *
 * Returns true on success, false with a Python exception on error.
 */
bool get_nss_fn(int mod_idx, nss_op_t op, nss_fn_t *out);

/*
 * Acquire/release the per-backend iteration lock.  Only backends that
 * are not thread-safe for iteration (FILES) actually lock; others are
 * no-ops.  The GIL is released while waiting for the lock.
 */
void nss_iter_lock(int mod_idx);
void nss_iter_unlock(int mod_idx);

#endif /* NSS_MODULE_H */
