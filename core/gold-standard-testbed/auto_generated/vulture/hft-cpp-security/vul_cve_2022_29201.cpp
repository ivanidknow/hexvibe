// Vulnerable: VUL-CVE-2022-29201
#include <algorithm>
#include <vector>

#include "tensorflow/core/platform/errors.h"

#define EIGEN_USE_THREADS
...
#include "tensorflow/core/kernels/reference_gemm.h"
#include "tensorflow/core/lib/core/errors.h"
#include "tensorflow/core/util/padding.h"

...


if __name__ == "__main__":
