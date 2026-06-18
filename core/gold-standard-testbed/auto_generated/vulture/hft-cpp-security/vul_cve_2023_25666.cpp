// Vulnerable: VUL-CVE-2023-25666
"//tensorflow/core:test_main",
        "//tensorflow/core:testlib",
    ],
)
// --- audio_ops.cc ---
#include "tensorflow/core/framework/shape_inference.h"
#include "tensorflow/core/lib/core/bits.h"

namespace tensorflow {
...
  int32_t window_size;
...

}  // namespace
}  // namespace ops
