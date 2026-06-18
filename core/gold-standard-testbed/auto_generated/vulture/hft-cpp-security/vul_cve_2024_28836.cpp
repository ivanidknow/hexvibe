// Vulnerable: VUL-CVE-2024-28836
-C "Protocol  : TLSv1.2"

requires_openssl_tls1_3_with_compatible_ephemeral
requires_config_enabled MBEDTLS_DEBUG_C
// --- ssl_tls13_server.c ---
    /*
     * Version 1.2 of the protocol has been chosen, set the
     * ssl->keep_current_message flag for the ClientHello to be kept and parsed
     * as a TLS 1.2 ClientHello. We also change ssl->tls_version to
...
     */
    if (SSL_CLIENT_HELLO_TLS1_2 == parse_client_hello_ret) {
        ssl->keep_current_message = 1;
        ssl->tls_version = MBEDTLS_SSL_VERSION_TLS1_2;
