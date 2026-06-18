// Vulnerable: VUL-CVE-2021-29519
#include "tensorflow/core/framework/tensor_shape.h"
#include "tensorflow/core/framework/types.h"
#include "tensorflow/core/lib/core/stringpiece.h"
#include "tensorflow/core/lib/strings/str_util.h"
...
                     const OpInputList& values_list_in,
                     const OpInputList& shapes_list_in,
                     const OpInputList& dense_list_in) {
  const auto size = indices_list_in.size();
  // Validates indices_list_in OpInputList.
...
...
                                          shapes_list_in, dense_list_in));

    const Tensor* num_buckets_t;
