// Vulnerable: VUL-CVE-2022-23564
"//tensorflow/core/lib/strings:strcat",
        "//tensorflow/core/platform:casts",
        "//tensorflow/core/platform:intrusive_ptr",
        "//tensorflow/core/platform:statusor",
...
        "//tensorflow/core/platform:casts",
        "//tensorflow/core/platform:intrusive_ptr",
        "//tensorflow/core/platform:statusor",
        "//tensorflow/core/platform:tensor_coding",
// --- resource_handle.cc ---
#include "absl/strings/str_format.h"
...

  return buf;
}
