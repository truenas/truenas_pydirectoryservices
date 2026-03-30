#ifndef KRB5_FLAGS_TABLE_H
#define KRB5_FLAGS_TABLE_H

#include <krb5.h>

typedef struct {
    krb5_flags flag;
    const char *name;
} krb5_flag_entry;

static const krb5_flag_entry krb5_flags_table[] = {
    { TKT_FLG_FORWARDABLE, "FORWARDABLE" },              /* 0x40000000 */
    { TKT_FLG_FORWARDED, "FORWARDED" },                  /* 0x20000000 */
    { TKT_FLG_PROXIABLE, "PROXIABLE" },                  /* 0x10000000 */
    { TKT_FLG_PROXY, "PROXY" },                          /* 0x08000000 */
    { TKT_FLG_MAY_POSTDATE, "MAY_POSTDATE" },            /* 0x04000000 */
    { TKT_FLG_POSTDATED, "POSTDATED" },                  /* 0x02000000 */
    { TKT_FLG_INVALID, "INVALID" },                      /* 0x01000000 */
    { TKT_FLG_RENEWABLE, "RENEWABLE" },                  /* 0x00800000 */
    { TKT_FLG_INITIAL, "INITIAL" },                      /* 0x00400000 */
    { TKT_FLG_PRE_AUTH, "PRE_AUTH" },                    /* 0x00200000 */
    { TKT_FLG_HW_AUTH, "HW_AUTH" },                      /* 0x00100000 */
    { TKT_FLG_TRANSIT_POLICY_CHECKED, "TRANSIT_POLICY_CHECKED" }, /* 0x00080000 */
    { TKT_FLG_OK_AS_DELEGATE, "OK_AS_DELEGATE" },        /* 0x00040000 */
    { TKT_FLG_ENC_PA_REP, "ENC_PA_REP" },                /* 0x00010000 */
    { TKT_FLG_ANONYMOUS, "ANONYMOUS" },                  /* 0x00008000 */
    { 0, NULL }
};

#endif /* KRB5_FLAGS_TABLE_H */