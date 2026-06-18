// Vulnerable: VUL-CVE-2022-23559
#include "tensorflow/lite/kernels/internal/tensor_utils.h"
#include "tensorflow/lite/kernels/kernel_util.h"

namespace tflite {
...
  TF_LITE_ENSURE(context, output_shape != nullptr);
  int k = 0;
  int embedding_size = 1;
  int lookup_size = 1;
  for (int i = 0; i < lookup_rank - 1; i++, k++) {
    const int dim = dense_shape->data.i32[i];
...
  const float* value_ptr = GetTensorData<float>(value);

  std::fill_n(output_ptr, output_size, 0.0f);
