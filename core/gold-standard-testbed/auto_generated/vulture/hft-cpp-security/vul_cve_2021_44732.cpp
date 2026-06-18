// Vulnerable: VUL-CVE-2021-44732
memcpy( dst, src, sizeof( mbedtls_ssl_session ) );

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if( src->peer_cert != NULL )
