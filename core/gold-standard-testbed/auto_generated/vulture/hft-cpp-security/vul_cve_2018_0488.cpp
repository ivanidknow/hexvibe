// Vulnerable: VUL-CVE-2018-0488
* SSLv3.0 MAC functions
 */
static void ssl_mac( mbedtls_md_context_t *md_ctx, unsigned char *secret,
                     unsigned char *buf, size_t len,
                     unsigned char *ctr, int type )
{
    unsigned char header[11];
...
    mbedtls_md_update( md_ctx, header,  11      );
    mbedtls_md_update( md_ctx, buf,     len     );
    mbedtls_md_finish( md_ctx, buf +    len     );
...
                      ssl->in_ctr, ssl->in_msgtype );
        }
        else
