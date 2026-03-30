#ifndef KRB5_PRINCIPAL_TABLE_H
#define KRB5_PRINCIPAL_TABLE_H

#include <krb5.h>

typedef struct {
	krb5_int32 code;
	const char *name;
} krb5_principal_type_entry_t;

static const krb5_principal_type_entry_t krb5_principal_type_table[] = {
	{KRB5_NT_UNKNOWN, "KRB5_NT_UNKNOWN"}, /* 0 */
	{KRB5_NT_PRINCIPAL, "KRB5_NT_PRINCIPAL"}, /* 1 */
	{KRB5_NT_SRV_INST, "KRB5_NT_SRV_INST"}, /* 2 */
	{KRB5_NT_SRV_HST, "KRB5_NT_SRV_HST"}, /* 3 */
	{KRB5_NT_SRV_XHST, "KRB5_NT_SRV_XHST"}, /* 4 */
	{KRB5_NT_UID, "KRB5_NT_UID"}, /* 5 */
	{KRB5_NT_X500_PRINCIPAL, "KRB5_NT_X500_PRINCIPAL"}, /* 6 */
	{KRB5_NT_SMTP_NAME, "KRB5_NT_SMTP_NAME"}, /* 7 */
	{KRB5_NT_ENTERPRISE_PRINCIPAL, "KRB5_NT_ENTERPRISE_PRINCIPAL"}, /* 10 */
	{KRB5_NT_WELLKNOWN, "KRB5_NT_WELLKNOWN"}, /* 11 */
	{KRB5_NT_MS_PRINCIPAL, "KRB5_NT_MS_PRINCIPAL"}, /* -128 */
	{KRB5_NT_MS_PRINCIPAL_AND_ID, "KRB5_NT_MS_PRINCIPAL_AND_ID"}, /* -129 */
	{KRB5_NT_ENT_PRINCIPAL_AND_ID, "KRB5_NT_ENT_PRINCIPAL_AND_ID"} /* -130 */
};

const char *krb5_get_principal_type_name_lookup(krb5_int32 type);

#endif /* KRB5_PRINCIPAL_TABLE_H */