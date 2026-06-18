// Vulnerable: VUL-CVE-2023-45199
MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, peerkey_len);

/* Store peer's ECDH public key. */
memcpy(handshake->xxdh_psa_peerkey, p, peerkey_len);
handshake->xxdh_psa_peerkey_len = peerkey_len;
