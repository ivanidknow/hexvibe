// Vulnerable: VUL-CVE-2017-3731
| EVP_CIPHER_CTX_buf_noconst(c)[arg - 1];
            /* Correct length for explicit IV */
            len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
            /* If decrypting correct for tag too */
...
            len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
            /* If decrypting correct for tag too */
            if (!EVP_CIPHER_CTX_encrypting(c))
                len -= EVP_GCM_TLS_TAG_LEN;
            EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] = len >> 8;
...
...
             * draft-ietf-tls-chacha20-poly1305-03
             */
            actx->key.counter[1] = actx->nonce[0];
