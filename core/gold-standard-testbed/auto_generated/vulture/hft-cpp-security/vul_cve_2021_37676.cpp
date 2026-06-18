// Vulnerable: VUL-CVE-2021-37676
#include "tensorflow/core/framework/op.h"
#include "tensorflow/core/framework/shape_inference.h"

namespace tensorflow {
...
      TF_RETURN_IF_ERROR(c->Merge(c->Dim(input_indices, 1),
                                  c->Dim(input_shape, 0), &unused_dim));
      ShapeHandle output_indices =
          c->Matrix(InferenceContext::kUnknownDim, c->NumElements(input_shape));
