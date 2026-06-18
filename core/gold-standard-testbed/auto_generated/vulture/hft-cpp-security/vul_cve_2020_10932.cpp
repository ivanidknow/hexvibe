// Vulnerable: VUL-CVE-2020-10932
= mbed TLS x.x.x branch released xxxx-xx-xx

Bugfix
// --- ecp.c ---
     */
    MBEDTLS_MPI_CHK( ecp_safe_invert_jac( grp, R, ! m_is_odd ) );
    MBEDTLS_MPI_CHK( ecp_normalize_jac( grp, R ) );

...
    }

    MBEDTLS_MPI_CHK( ecp_normalize_mxz( grp, R ) );
