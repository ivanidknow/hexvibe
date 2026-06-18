// Vulnerable: VUL-CVE-2020-36475
all_final += cli-rsa-sha256.crt.der

 cli-rsa.key.der: $(cli_crt_key_file_rsa)
	$(OPENSSL) pkey -in $< -out $@ -inform PEM -outform DER
all_final += cli-rsa.key.der
// --- bignum.c ---
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    /*
     * Init temps and window size
...
...
#endif /* MBEDTLS_CIPHER_MODE_AEAD */

#endif /* MBEDTLS_CIPHER_C */
