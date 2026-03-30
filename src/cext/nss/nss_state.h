// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef TRUENAS_NSS_STATE_H
#define TRUENAS_NSS_STATE_H

#include <Python.h>

/* Module state - stores PyStructSequence types, enum types, and exception */
typedef struct {
	PyObject *PasswdResultType;
	PyObject *GroupResultType;
	PyObject *NssModuleEnum;
	PyObject *NssReturnCodeEnum;
	PyObject *NssError;
	PyObject *NssSourceEnum; /* the StrEnum class itself */
	PyObject *NssSourceMembers[3]; /* [FILES, SSS, WINBIND] indexed by NSS_MOD_* */
} truenas_pynss_state_t;

/* Get module state; NULL uses PyState_FindModule */
truenas_pynss_state_t *get_truenas_pynss_state(PyObject *module);

/*
 * Returns 1 if the current Python exception is a NssError whose return_code
 * equals NSS_STATUS_UNAVAIL, clearing the exception in that case.
 * Returns 0 for any other exception or error state, leaving it intact.
 */
int nss_err_is_unavail(void);

#endif /* TRUENAS_NSS_STATE_H */
