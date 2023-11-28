lib_sources += files('hash.c')
if openssl_dep.found()
    subdir('openssl')
elif get_variable('afalg') == true
    subdir('afalg')
else
    subdir('bundled')
endif
