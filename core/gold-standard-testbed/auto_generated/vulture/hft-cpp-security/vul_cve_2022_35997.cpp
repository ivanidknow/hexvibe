// Vulnerable: VUL-CVE-2022-35997
#include "tensorflow/core/framework/op_def_builder.h"
#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/framework/tensor.h"
#include "tensorflow/core/framework/tensor_shape.h"
...
#include "tensorflow/core/lib/core/stringpiece.h"
#include "tensorflow/core/lib/strings/str_util.h"
#include "tensorflow/core/platform/fingerprint.h"
#include "tensorflow/core/platform/strong_hash.h"
...
    const Tensor* sep_t;
...


class SparseCrossHashedOpTest(BaseSparseCrossOpTest):
