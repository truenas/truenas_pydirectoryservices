#ifndef KRB5_ENCTYPE_TABLE_H
#define KRB5_ENCTYPE_TABLE_H

#include <krb5.h>
#include <stdbool.h>

typedef struct {
	krb5_enctype code;
	const char *name;
	bool deprecated;
} krb5_enctype_entry_t;

static const krb5_enctype_entry_t krb5_enctype_table[] = {
	{ENCTYPE_NULL, "ENCTYPE_NULL", false}, /* 0x0000 */
	{ENCTYPE_DES_CBC_CRC, "ENCTYPE_DES_CBC_CRC", true}, /* 0x0001 - DEPRECATED */
	{ENCTYPE_DES_CBC_MD4, "ENCTYPE_DES_CBC_MD4", true}, /* 0x0002 - DEPRECATED */
	{ENCTYPE_DES_CBC_MD5, "ENCTYPE_DES_CBC_MD5", true}, /* 0x0003 - DEPRECATED */
	{ENCTYPE_DES3_CBC_SHA1, "ENCTYPE_DES3_CBC_SHA1", true}, /* 0x0010 - DEPRECATED */
	{ENCTYPE_AES128_CTS_HMAC_SHA1_96, "ENCTYPE_AES128_CTS_HMAC_SHA1_96", false}, /* 0x0011 */
	{ENCTYPE_AES256_CTS_HMAC_SHA1_96, "ENCTYPE_AES256_CTS_HMAC_SHA1_96", false}, /* 0x0012 */
	{ENCTYPE_AES128_CTS_HMAC_SHA256_128, "ENCTYPE_AES128_CTS_HMAC_SHA256_128", false}, /* 0x0013 */
	{ENCTYPE_AES256_CTS_HMAC_SHA384_192, "ENCTYPE_AES256_CTS_HMAC_SHA384_192", false}, /* 0x0014 */
	{ENCTYPE_ARCFOUR_HMAC, "ENCTYPE_ARCFOUR_HMAC", true}, /* 0x0017 - DEPRECATED */
	{ENCTYPE_ARCFOUR_HMAC_EXP, "ENCTYPE_ARCFOUR_HMAC_EXP", true}, /* 0x0018 - DEPRECATED */
	{ENCTYPE_CAMELLIA128_CTS_CMAC, "ENCTYPE_CAMELLIA128_CTS_CMAC", false}, /* 0x0019 */
	{ENCTYPE_CAMELLIA256_CTS_CMAC, "ENCTYPE_CAMELLIA256_CTS_CMAC", false}, /* 0x001a */
	{ENCTYPE_UNKNOWN, "ENCTYPE_UNKNOWN", false} /* 0x01ff */
};

const char *krb5_get_enctype_name_lookup(krb5_enctype enctype);
bool krb5_get_enctype_deprecated(krb5_enctype enctype);

#endif /* KRB5_ENCTYPE_TABLE_H */