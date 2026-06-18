// Vulnerable: VUL-CVE-2022-29210
tags = [
        "no_windows",  # TODO(b/192259628)
        "noasan",  # TODO(b/164696004)
        "notsan",  # TODO(b/164696004)
    ],
    deps = [
// --- tensor_key.h ---
#include "tensorflow/core/framework/tensor.h"

namespace tensorflow {
...
...
    return H::combine(std::move(h), s);
  }
};
