// Vulnerable: VUL-CVE-2017-14032
chain was not verified due to an internal error (including in the verify
     callback) or chain length limitations.

= mbed TLS 2.5.1 released 2017-06-21
// --- error.c ---
        if( use_ret == -(MBEDTLS_ERR_X509_BUFFER_TOO_SMALL) )
            mbedtls_snprintf( buf, buflen, "X509 - Destination buffer is too small" );
#endif /* MBEDTLS_X509_USE_C || MBEDTLS_X509_CREATE_C */
        // END generated code
// --- error.h ---
 * PEM       1   9
...
 *                 information, please see \c x509parse_verify()
 *
 * \param conf     SSL configuration
