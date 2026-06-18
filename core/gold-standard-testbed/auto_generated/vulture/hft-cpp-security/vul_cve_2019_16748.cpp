// Vulnerable: VUL-CVE-2019-16748
}

static void test_wolfSSL_X509_get_version(void){
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
...
    test_wolfSSL_i2c_ASN1_INTEGER();
    test_wolfSSL_X509_check_ca();
    test_wolfSSL_DES_ncbc();
    test_wolfSSL_AES_cbc_encrypt();
// --- asn.c ---
                  (nameType == ISSUER) ? &cert->issuerName : &cert->subjectName;
...
    AM_CFLAGS="$AM_CFLAGS -DHAVE_FFDHE_2048 -DHAVE_FFDHE_3072 -DFP_MAX_BITS=8192"
fi
AM_CONDITIONAL([BUILD_ALL], [test "x$ENABLED_ALL" = "xyes"])
