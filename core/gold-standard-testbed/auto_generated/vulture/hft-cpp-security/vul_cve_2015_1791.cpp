// Vulnerable: VUL-CVE-2015-1791
p = d = (unsigned char *)s->init_msg;
    n2l(p, s->session->tlsext_tick_lifetime_hint);
    n2s(p, ticklen);
// --- ssl.h ---
# define SSL_F_SSL_SCAN_CLIENTHELLO_TLSEXT                320
# define SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT                321
# define SSL_F_SSL_SESSION_NEW                            189
# define SSL_F_SSL_SESSION_PRINT_FP                       190
// --- ssl_err.c ---
    {ERR_FUNC(SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT),
     "SSL_SCAN_SERVERHELLO_TLSEXT"},
...
                         const unsigned char *limit);
__owur int ssl_cipher_id_cmp(const SSL_CIPHER *a, const SSL_CIPHER *b);
DECLARE_OBJ_BSEARCH_GLOBAL_CMP_FN(SSL_CIPHER, SSL_CIPHER, ssl_cipher_id);
