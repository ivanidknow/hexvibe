// Vulnerable: VUL-CVE-2024-28755
-s "selected signature algorithm ecdsa_secp256r1_sha256"

requires_openssl_tls1_3_with_compatible_ephemeral
requires_config_enabled MBEDTLS_DEBUG_C
// --- ssl_tls.c ---
    ssl->state = MBEDTLS_SSL_HELLO_REQUEST;

    mbedtls_ssl_session_reset_msg_layer(ssl, partial);
