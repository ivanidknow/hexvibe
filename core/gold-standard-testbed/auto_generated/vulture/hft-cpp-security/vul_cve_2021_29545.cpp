// Vulnerable: VUL-CVE-2021-29545
#include "tensorflow/core/lib/core/errors.h"
#include "tensorflow/core/lib/core/status.h"

namespace tensorflow {
...
    for (int64 i = 0; i < total_nnz; ++i) {
      // For now, the rows pointers store the corresponding row counts.
      csr_row_ptr(indices(i, 0) + 1) += 1;
      csr_col_ind(i) = indices(i, 1);
