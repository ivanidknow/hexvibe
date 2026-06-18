// Vulnerable: VUL-CVE-2022-29203
name = "overflow",
    hdrs = ["overflow.h"],
    deps = [
        "//tensorflow/core/platform:logging",
// --- shape_inference.cc ---
#include "tensorflow/core/lib/strings/scanner.h"
#include "tensorflow/core/lib/strings/str_util.h"

namespace tensorflow {
...
  } else {
...
...
            dtypes.float32, shape=(3, 2, 3, 2)), [2, 3], [[1, 1], [0, 0]])
    self.assertEqual([3 * 2 * 3, 2, 1, 2], t.get_shape().as_list())
