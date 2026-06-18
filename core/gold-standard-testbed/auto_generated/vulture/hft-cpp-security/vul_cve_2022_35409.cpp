// Vulnerable: VUL-CVE-2022-35409
#if defined(MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE) && defined(MBEDTLS_SSL_SRV_C)
/*
 * Without any SSL context, check if a datagram looks like a ClientHello with
 * a valid cookie, and if it doesn't, generate a HelloVerifyRequest message.
 * Both input and output include full DTLS headers.
 *
...
 */
static int ssl_check_dtls_clihlo_cookie(
                           mbedtls_ssl_cookie_write_t *f_cookie_write,
                           mbedtls_ssl_cookie_check_t *f_cookie_check,
...
         */
        if( ssl->in_msg[6] != 0 || ssl->in_msg[7] != 0 || ssl->in_msg[8] != 0 ||
            memcmp( ssl->in_msg + 1, ssl->in_msg + 9, 3 ) != 0 )
