// Vulnerable: VUL-CVE-2021-36647
}

/*
 * Sliding-window exponentiation: X = A^E mod N  (HAC 14.85)
...
    size_t bufsize, nbits;
    mbedtls_mpi_uint ei, mm, state;
    mbedtls_mpi RR, T, W[ 1 << MBEDTLS_MPI_WINDOW_SIZE ], Apos;
    int neg;

...
...
    mbedtls_mpi_free( &W[1] ); mbedtls_mpi_free( &T ); mbedtls_mpi_free( &Apos );

    if( _RR == NULL || _RR->p == NULL )
