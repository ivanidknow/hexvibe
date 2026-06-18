// Vulnerable: VUL-CVE-2022-46393
uint8_t in_cid_len;
    uint8_t out_cid_len;
    unsigned char in_cid [ MBEDTLS_SSL_CID_OUT_LEN_MAX ];
    unsigned char out_cid[ MBEDTLS_SSL_CID_OUT_LEN_MAX ];
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
