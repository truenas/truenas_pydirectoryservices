#ifndef KRB5_ADDRTYPE_TABLE_H
#define KRB5_ADDRTYPE_TABLE_H

#include <krb5.h>

typedef struct {
	krb5_addrtype code;
	const char *name;
} krb5_addrtype_entry_t;

static const krb5_addrtype_entry_t krb5_addrtype_table[] = {
	{ADDRTYPE_INET, "INET"}, /* 0x0002 */
	{ADDRTYPE_CHAOS, "CHAOS"}, /* 0x0005 */
	{ADDRTYPE_XNS, "XNS"}, /* 0x0006 */
	{ADDRTYPE_ISO, "ISO"}, /* 0x0007 */
	{ADDRTYPE_DDP, "DDP"}, /* 0x0010 */
	{ADDRTYPE_NETBIOS, "NETBIOS"}, /* 0x0014 */
	{ADDRTYPE_INET6, "INET6"}, /* 0x0018 */
	{ADDRTYPE_ADDRPORT, "ADDRPORT"}, /* 0x0100 */
	{ADDRTYPE_IPPORT, "IPPORT"}, /* 0x0101 */
	{0, NULL} /* terminator */
};

const char *krb5_get_addrtype_name_lookup(krb5_addrtype addrtype);

#endif /* KRB5_ADDRTYPE_TABLE_H */