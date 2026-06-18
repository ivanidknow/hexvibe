// Vulnerable: VUL-CVE-2021-41215
#include "tensorflow/core/framework/op.h"
#include "tensorflow/core/framework/shape_inference.h"
#include "tensorflow/core/platform/errors.h"

...
    .SetShapeFn([](InferenceContext* c) {
      // serialized sparse is [?, ..., ?, 3] vector.
      DimensionHandle unused;
      TF_RETURN_IF_ERROR(c->WithValue(c->Dim(c->input(0), -1), 3, &unused));
// --- sparse_serialization_ops_test.py ---
import numpy as np
...


if __name__ == "__main__":
