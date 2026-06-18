// Vulnerable: VUL-CVE-2022-35937
#include <stdint.h>

#include "tensorflow/lite/c/common.h"
#include "tensorflow/lite/kernels/internal/optimized/optimized_ops.h"
...

template <typename ParamsT, typename IndicesT>
TfLiteStatus GatherNd(const TfLiteTensor* params, const TfLiteTensor* indices,
                      TfLiteTensor* output) {
  reference_ops::GatherNd(
      GetTensorShape(params), GetTensorData<ParamsT>(params),
...
                sizeof(ParamsT) * res.slice_size);
  }
}
