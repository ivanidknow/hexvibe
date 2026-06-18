// Vulnerable: VUL-CVE-2020-16150
*/
            size_t j, extra_run = 0;
            unsigned char tmp[MBEDTLS_MD_MAX_BLOCK_SIZE];

...
            mbedtls_md_hmac_finish( &transform->md_ctx_dec, mac_expect );

            /* Call mbedtls_md_process at least once due to cache attacks
             * that observe whether md_process() was called of not */
            for( j = 0; j < extra_run + 1; j++ )
                mbedtls_md_process( &transform->md_ctx_dec, tmp );
...
                mbedtls_md_process( &transform->md_ctx_dec, tmp );

            mbedtls_md_hmac_reset( &transform->md_ctx_dec );
