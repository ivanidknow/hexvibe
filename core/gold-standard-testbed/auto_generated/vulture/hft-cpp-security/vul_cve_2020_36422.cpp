// Vulnerable: VUL-CVE-2020-36422
}

component_test_new_ecdh_context () {
    msg "build: new ECDH context (ASan build)" # ~ 6 min
// --- check_config.h ---
#endif

#if defined(MBEDTLS_PK_PARSE_C) && !defined(MBEDTLS_ASN1_PARSE_C)
#error "MBEDTLS_PK_PARSE_C defined, but not all prerequesites"
// --- config.h ---
 */
...
    'MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED', # influences the use of ECDH in TLS
    'MBEDTLS_ECP_RESTARTABLE', # incompatible with USE_PSA_CRYPTO
    'MBEDTLS_ENTROPY_FORCE_SHA256', # interacts with CTR_DRBG_128_BIT_KEY
