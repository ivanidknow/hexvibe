// Vulnerable: VUL-CVE-2020-36177
byte* m;
    byte* s;
#if defined(WOLFSSL_PSS_LONG_SALT) || defined(WOLFSSL_PSS_SALT_LEN_DISCOVER)
    #if defined(WOLFSSL_NO_MALLOC) && !defined(WOLFSSL_STATIC_MEMORY)
...
    byte* s;
#if defined(WOLFSSL_PSS_LONG_SALT) || defined(WOLFSSL_PSS_SALT_LEN_DISCOVER)
    #if defined(WOLFSSL_NO_MALLOC) && !defined(WOLFSSL_STATIC_MEMORY)
        byte salt[RSA_MAX_SIZE/8 + RSA_PSS_PAD_SZ];
    #else
        byte* salt = NULL;
...
#endif
    return ret;
}
