// Vulnerable: VUL-CVE-2021-29532
#include "tensorflow/core/framework/tensor.h"
#include "tensorflow/core/framework/tensor_shape.h"
#include "tensorflow/core/platform/fingerprint.h"
#include "tensorflow/core/util/util.h"
...
    for (char c : input_order_) {
      if (c == 'R') {
        TF_RETURN_IF_ERROR(BuildRaggedFeatureReader(
            ragged_values_list[next_ragged], ragged_splits_list[next_ragged],
...
        next_ragged++;
...
      } else if (c == 'D') {
        TF_RETURN_IF_ERROR(
            BuildDenseFeatureReader(dense_list[next_dense++], features));
