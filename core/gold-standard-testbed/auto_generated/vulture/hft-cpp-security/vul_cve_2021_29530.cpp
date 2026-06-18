// Vulnerable: VUL-CVE-2021-29530
#include <numeric>
#include <vector>

#define EIGEN_USE_THREADS
...
    int64 num_rows;
    int batch_size;
    ValidateInputs(ctx, *input_matrix, input_permutation_indices, &batch_size,
                   &num_rows);

    // Allocate batch pointers.
...
    }
  }
};
