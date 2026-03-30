from setuptools import setup, Extension

truenas_nss_ext = Extension(
    'truenas_pynss',
    sources=[
        'src/cext/nss/nss_module.c',
        'src/cext/nss/util_enum.c',
        'src/cext/nss/pwd.c',
        'src/cext/nss/grp.c',
        'src/cext/nss/nss.c',
    ],
    include_dirs=['src/cext/nss'],
    libraries=['dl'],
)

truenas_pykrb5_ext = Extension(
    'truenas_pykrb5',
    sources=[
        'src/cext/krb5/truenas_pykrb5.c',
        'src/cext/krb5/truenas_pykeytab.c',
        'src/cext/krb5/truenas_pykeytab_entry.c',
        'src/cext/krb5/truenas_pykeytab_iter.c',
        'src/cext/krb5/truenas_pycredcache.c',
        'src/cext/krb5/truenas_pycredcache_cred.c',
        'src/cext/krb5/truenas_pycredcache_iter.c',
        'src/cext/krb5/truenas_pykrb5_utils.c',
        'src/cext/krb5/truenas_pykrb5err.c',
        'src/cext/krb5/truenas_pyerrcode.c',
        'src/cext/krb5/truenas_pyenctype.c',
        'src/cext/krb5/truenas_pyprincipaltype.c',
        'src/cext/krb5/truenas_pytktflags.c',
        'src/cext/krb5/truenas_pykrb5_kinit.c',
    ],
    include_dirs=['src/cext/krb5'],
    libraries=['krb5'],
)

setup(
    ext_modules=[truenas_nss_ext, truenas_pykrb5_ext],
    packages=['truenas_pynss', 'truenas_pykrb5', 'truenas_krb5conf_pyutils'],
    package_dir={
        'truenas_pynss': 'stubs/truenas_pynss',
        'truenas_pykrb5': 'stubs/truenas_pykrb5',
        'truenas_krb5conf_pyutils': 'src/truenas_krb5conf_pyutils',
    },
    package_data={
        'truenas_pynss': ['*.pyi', 'py.typed'],
        'truenas_pykrb5': ['*.pyi', 'py.typed'],
    },
)
