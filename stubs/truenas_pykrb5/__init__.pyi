# SPDX-License-Identifier: LGPL-3.0-or-later
from datetime import datetime
from typing import Any, ClassVar, Iterator, final
from enum import IntEnum, IntFlag

# ── Enums ──────────────────────────────────────────────────────────────────

class KRB5ErrCode(IntEnum):
    KRB5KDC_ERR_NONE = 0
    KRB5KDC_ERR_NAME_EXP = 1
    KRB5KDC_ERR_SERVICE_EXP = 2
    KRB5KDC_ERR_BAD_PVNO = 3
    KRB5KDC_ERR_C_OLD_MAST_KVNO = 4
    KRB5KDC_ERR_S_OLD_MAST_KVNO = 5
    KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN = 6
    KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN = 7
    KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE = 8
    KRB5KDC_ERR_NULL_KEY = 9
    KRB5KDC_ERR_CANNOT_POSTDATE = 10
    KRB5KDC_ERR_NEVER_VALID = 11
    KRB5KDC_ERR_POLICY = 12
    KRB5KDC_ERR_BADOPTION = 13
    KRB5KDC_ERR_ETYPE_NOSUPP = 14
    KRB5KDC_ERR_SUMTYPE_NOSUPP = 15
    KRB5KDC_ERR_PADATA_TYPE_NOSUPP = 16
    KRB5KDC_ERR_TRTYPE_NOSUPP = 17
    KRB5KDC_ERR_CLIENT_REVOKED = 18
    KRB5KDC_ERR_SERVICE_REVOKED = 19
    KRB5KDC_ERR_TGT_REVOKED = 20
    KRB5KDC_ERR_CLIENT_NOTYET = 21
    KRB5KDC_ERR_SERVICE_NOTYET = 22
    KRB5KDC_ERR_KEY_EXP = 23
    KRB5KDC_ERR_PREAUTH_FAILED = 24
    KRB5KDC_ERR_PREAUTH_REQUIRED = 25
    KRB5KDC_ERR_SERVER_NOMATCH = 26
    KRB5KRB_AP_ERR_BAD_INTEGRITY = 31
    KRB5KRB_AP_ERR_TKT_EXPIRED = 32
    KRB5KRB_AP_ERR_TKT_NYV = 33
    KRB5KRB_AP_ERR_REPEAT = 34
    KRB5KRB_AP_ERR_NOT_US = 35
    KRB5KRB_AP_ERR_BADMATCH = 36
    KRB5KRB_AP_ERR_SKEW = 37
    KRB5KRB_AP_ERR_BADADDR = 38
    KRB5KRB_AP_ERR_BADVERSION = 39
    KRB5KRB_AP_ERR_MSG_TYPE = 40
    KRB5KRB_AP_ERR_MODIFIED = 41
    KRB5KRB_AP_ERR_BADORDER = 42
    KRB5KRB_AP_ERR_ILL_CR_TKT = 43
    KRB5KRB_AP_ERR_BADKEYVER = 44
    KRB5KRB_AP_ERR_NOKEY = 45
    KRB5KRB_AP_ERR_MUT_FAIL = 46
    KRB5KRB_AP_ERR_BADDIRECTION = 47
    KRB5KRB_AP_ERR_METHOD = 48
    KRB5KRB_AP_ERR_BADSEQ = 49
    KRB5KRB_AP_ERR_INAPP_CKSUM = 50
    KRB5KRB_AP_PATH_NOT_ACCEPTED = 51
    KRB5KRB_ERR_RESPONSE_TOO_BIG = 52
    KRB5KRB_ERR_GENERIC = 60
    KRB5KRB_ERR_FIELD_TOOLONG = 61
    KRB5_ERR_RCSID = 128
    KRB5_LIBOS_BADLOCKFLAG = 129
    KRB5_LIBOS_CANTREADPWD = 130
    KRB5_LIBOS_BADPWDMATCH = 131
    KRB5_LIBOS_PWDINTR = 132
    KRB5_PARSE_ILLCHAR = 133
    KRB5_PARSE_MALFORMED = 134
    KRB5_CONFIG_CANTOPEN = 135
    KRB5_CONFIG_BADFORMAT = 136
    KRB5_CONFIG_NOTENUFSPACE = 137
    KRB5_BADMSGTYPE = 138
    KRB5_CC_BADNAME = 139
    KRB5_CC_UNKNOWN_TYPE = 140
    KRB5_CC_NOTFOUND = 141
    KRB5_CC_END = 142
    KRB5_NO_TKT_SUPPLIED = 143
    KRB5KRB_AP_WRONG_PRINC = 144
    KRB5KRB_AP_ERR_TKT_INVALID = 145
    KRB5_PRINC_NOMATCH = 146
    KRB5_KDCREP_MODIFIED = 147
    KRB5_KDCREP_SKEW = 148
    KRB5_IN_TKT_REALM_MISMATCH = 149
    KRB5_PROG_ETYPE_NOSUPP = 150
    KRB5_PROG_KEYTYPE_NOSUPP = 151
    KRB5_WRONG_ETYPE = 152
    KRB5_PROG_SUMTYPE_NOSUPP = 153
    KRB5_REALM_UNKNOWN = 154
    KRB5_SERVICE_UNKNOWN = 155
    KRB5_KDC_UNREACH = 156
    KRB5_NO_LOCALNAME = 157
    KRB5_MUTUAL_FAILED = 158
    KRB5_RC_TYPE_EXISTS = 159
    KRB5_RC_MALLOC = 160
    KRB5_RC_TYPE_NOTFOUND = 161
    KRB5_RC_UNKNOWN = 162
    KRB5_RC_REPLAY = 163
    KRB5_RC_IO = 164
    KRB5_RC_NOIO = 165
    KRB5_RC_PARSE = 166
    KRB5_RC_IO_EOF = 167
    KRB5_RC_IO_MALLOC = 168
    KRB5_RC_IO_PERM = 169
    KRB5_RC_IO_IO = 170
    KRB5_RC_IO_UNKNOWN = 171
    KRB5_RC_IO_SPACE = 172
    KRB5_TRANS_CANTOPEN = 173
    KRB5_TRANS_BADFORMAT = 174
    KRB5_LNAME_CANTOPEN = 175
    KRB5_LNAME_NOTRANS = 176
    KRB5_LNAME_BADFORMAT = 177
    KRB5_CRYPTO_INTERNAL = 178
    KRB5_KT_BADNAME = 179
    KRB5_KT_UNKNOWN_TYPE = 180
    KRB5_KT_NOTFOUND = 181
    KRB5_KT_END = 182
    KRB5_KT_NOWRITE = 183
    KRB5_KT_IOERR = 184
    KRB5_NO_TKT_IN_RLM = 185
    KRB5DES_BAD_KEYPAR = 186
    KRB5DES_WEAK_KEY = 187
    KRB5_BAD_ENCTYPE = 188
    KRB5_BAD_KEYSIZE = 189
    KRB5_BAD_MSIZE = 190
    KRB5_CC_TYPE_EXISTS = 191
    KRB5_KT_TYPE_EXISTS = 192
    KRB5_CC_IO = 193
    KRB5_FCC_PERM = 194
    KRB5_FCC_NOFILE = 195
    KRB5_FCC_INTERNAL = 196
    KRB5_CC_WRITE = 197
    KRB5_CC_NOMEM = 198
    KRB5_CC_FORMAT = 199
    KRB5_INVALID_FLAGS = 201
    KRB5_NO_2ND_TKT = 202
    KRB5_NOCREDS_SUPPLIED = 203
    KRB5_SENDAUTH_BADAUTHVERS = 204
    KRB5_SENDAUTH_BADAPPLVERS = 205
    KRB5_SENDAUTH_BADRESPONSE = 206
    KRB5_SENDAUTH_REJECTED = 207
    KRB5_PREAUTH_BAD_TYPE = 208
    KRB5_PREAUTH_NO_KEY = 209
    KRB5_PREAUTH_FAILED = 210
    KRB5_RCACHE_BADVNO = 211
    KRB5_CCACHE_BADVNO = 212
    KRB5_KEYTAB_BADVNO = 213
    KRB5_PROG_ATYPE_NOSUPP = 214
    KRB5_RC_REQUIRED = 215
    KRB5_ERR_BAD_HOSTNAME = 216
    KRB5_ERR_HOST_REALM_UNKNOWN = 217
    KRB5_SNAME_UNSUPP_NAMETYPE = 218
    KRB5KRB_AP_ERR_V4_REPLY = 219
    KRB5_REALM_CANT_RESOLVE = 220
    KRB5_TKT_NOT_FORWARDABLE = 221
    KRB5_FWD_BAD_PRINCIPAL = 222
    KRB5_GET_IN_TKT_LOOP = 223
    KRB5_CONFIG_NODEFREALM = 224
    KRB5_SAM_UNSUPPORTED = 225
    KRB5_KT_NAME_TOOLONG = 229
    KRB5_KT_KVNONOTFOUND = 230
    KRB5_APPL_EXPIRED = 231
    KRB5_LIB_EXPIRED = 232
    KRB5_CHPW_PWDNULL = 233
    KRB5_CHPW_FAIL = 234
    KRB5_KT_FORMAT = 235
    KRB5_NOPERM_ETYPE = 236
    KRB5_CONFIG_ETYPE_NOSUPP = 237
    KRB5_OBSOLETE_FN = 238
    KRB5_EAI_FAIL = 239
    KRB5_EAI_NODATA = 240
    KRB5_EAI_NONAME = 241
    KRB5_EAI_SERVICE = 242
    KRB5_ERR_NUMERIC_REALM = 243

class KRB5EncType(IntEnum):
    ENCTYPE_NULL = 0
    ENCTYPE_DES_CBC_CRC = 1
    ENCTYPE_DES_CBC_MD4 = 2
    ENCTYPE_DES_CBC_MD5 = 3
    ENCTYPE_DES3_CBC_SHA1 = 16
    ENCTYPE_AES128_CTS_HMAC_SHA1_96 = 17
    ENCTYPE_AES256_CTS_HMAC_SHA1_96 = 18
    ENCTYPE_AES128_CTS_HMAC_SHA256_128 = 19
    ENCTYPE_AES256_CTS_HMAC_SHA384_192 = 20
    ENCTYPE_ARCFOUR_HMAC = 23
    ENCTYPE_ARCFOUR_HMAC_EXP = 24
    ENCTYPE_CAMELLIA128_CTS_CMAC = 25
    ENCTYPE_CAMELLIA256_CTS_CMAC = 26
    ENCTYPE_UNKNOWN = 511

class KRB5PrincipalType(IntEnum):
    KRB5_NT_UNKNOWN = 0
    KRB5_NT_PRINCIPAL = 1
    KRB5_NT_SRV_INST = 2
    KRB5_NT_SRV_HST = 3
    KRB5_NT_SRV_XHST = 4
    KRB5_NT_UID = 5
    KRB5_NT_X500_PRINCIPAL = 6
    KRB5_NT_SMTP_NAME = 7
    KRB5_NT_ENTERPRISE_PRINCIPAL = 10
    KRB5_NT_WELLKNOWN = 11
    KRB5_NT_MS_PRINCIPAL = -128
    KRB5_NT_MS_PRINCIPAL_AND_ID = -129
    KRB5_NT_ENT_PRINCIPAL_AND_ID = -130

class KRB5TktFlags(IntFlag):
    FORWARDABLE = 0x40000000
    FORWARDED = 0x20000000
    PROXIABLE = 0x10000000
    PROXY = 0x08000000
    MAY_POSTDATE = 0x04000000
    POSTDATED = 0x02000000
    INVALID = 0x01000000
    RENEWABLE = 0x00800000
    INITIAL = 0x00400000
    PRE_AUTH = 0x00200000
    HW_AUTH = 0x00100000
    TRANSIT_POLICY_CHECKED = 0x00080000
    OK_AS_DELEGATE = 0x00040000
    ENC_PA_REP = 0x00010000
    ANONYMOUS = 0x00008000

# ── Exception ──────────────────────────────────────────────────────────────

class KRB5Error(RuntimeError):
    code: int
    context_error: str
    name: str
    location: str

# ── Struct sequences ───────────────────────────────────────────────────────

@final
class KeyInfo(tuple[Any, ...]):
    n_sequence_fields: ClassVar[int]
    n_fields: ClassVar[int]
    n_unnamed_fields: ClassVar[int]
    @property
    def enctype(self) -> KRB5EncType: ...
    @property
    def contents(self) -> bytes: ...
    @property
    def deprecated(self) -> bool: ...

@final
class PrincipalInfo(tuple[Any, ...]):
    n_sequence_fields: ClassVar[int]
    n_fields: ClassVar[int]
    n_unnamed_fields: ClassVar[int]
    @property
    def realm(self) -> str: ...
    @property
    def components(self) -> tuple[str, ...]: ...
    @property
    def principal_type(self) -> KRB5PrincipalType: ...

@final
class AddressInfo(tuple[Any, ...]):
    n_sequence_fields: ClassVar[int]
    n_fields: ClassVar[int]
    n_unnamed_fields: ClassVar[int]
    @property
    def addrtype(self) -> str: ...
    @property
    def contents(self) -> bytes: ...

@final
class AuthDataInfo(tuple[Any, ...]):
    n_sequence_fields: ClassVar[int]
    n_fields: ClassVar[int]
    n_unnamed_fields: ClassVar[int]
    @property
    def ad_type(self) -> int: ...
    @property
    def contents(self) -> bytes: ...

# ── Keytab types ───────────────────────────────────────────────────────────

@final
class KeytabEntry:
    @property
    def timestamp(self) -> datetime: ...
    @property
    def vno(self) -> int: ...
    @property
    def secret_key(self) -> KeyInfo: ...
    @property
    def principal(self) -> PrincipalInfo: ...

@final
class KeytabIter(Iterator[KeytabEntry]):
    def __next__(self) -> KeytabEntry: ...

@final
class Keytab:
    @property
    def name(self) -> str: ...
    def iter_keytab(self) -> KeytabIter: ...
    def __iter__(self) -> KeytabIter: ...
    def add_entry(self, *, principal: str, enctype: KRB5EncType, vno: int = ..., password: str | None = ..., key: bytes | None = ...) -> None: ...
    def remove_entry(self, *, principal: str, enctype: KRB5EncType | None = ..., vno: int | None = ...) -> None: ...
    def as_bytes(self) -> bytes: ...

# ── Credential cache types ─────────────────────────────────────────────────

@final
class CcacheCred:
    @property
    def client_principal(self) -> PrincipalInfo: ...
    @property
    def server_principal(self) -> PrincipalInfo: ...
    @property
    def authtime(self) -> datetime: ...
    @property
    def starttime(self) -> datetime: ...
    @property
    def endtime(self) -> datetime: ...
    @property
    def renew_till(self) -> datetime: ...
    @property
    def addresses(self) -> list[AddressInfo]: ...
    @property
    def keyblock(self) -> KeyInfo: ...
    @property
    def is_skey(self) -> bool: ...
    @property
    def ticket_flags(self) -> KRB5TktFlags: ...
    @property
    def authdata(self) -> list[AuthDataInfo]: ...

@final
class CcacheIter(Iterator[CcacheCred]):
    def __next__(self) -> CcacheCred: ...

@final
class Ccache:
    @property
    def name(self) -> str: ...
    @property
    def principal(self) -> str: ...
    def iter_credentials(self) -> CcacheIter: ...
    def kdestroy(self) -> None: ...

# ── Module-level functions ─────────────────────────────────────────────────

def get_keytab(*, filename: str | None = ..., data: bytes | None = ...) -> Keytab: ...
def get_ccache(*, ccache_name: str | None = ..., config_file: str | None = ...) -> Ccache: ...
def get_init_creds_keytab(*, principal: str, keytab: str | None = ..., ccache_name: str | None = ..., config_file: str | None = ...) -> Ccache: ...
def get_init_creds_password(*, principal: str, password: str, ccache_name: str | None = ..., config_file: str | None = ...) -> Ccache: ...
