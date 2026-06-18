// Vulnerable: VUL-CVE-2024-23170
#include "constant_time_internal.h"
#include "mbedtls/constant_time.h"

#include <string.h>
...
cleanup:
    mbedtls_mpi_free(&R);

    return ret;
...
         * T = T * Vf mod N
...
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&T, &T, &ctx->Vf));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&T, &T, &ctx->N));
    }
