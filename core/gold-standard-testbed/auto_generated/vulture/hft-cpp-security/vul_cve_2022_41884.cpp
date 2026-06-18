// Vulnerable: VUL-CVE-2022-41884
":bfloat16_lib",
        ":numpy_lib",
        "//tensorflow/c:c_api_no_xla",
        "//tensorflow/core:lib",
// --- ndarray_tensor_bridge.cc ---
==============================================================================*/

// Must be included first.
#include "tensorflow/python/lib/core/numpy.h"
...
// Must be included first.
...


class TFETensorUtilTest(test_util.TensorFlowTestCase):
