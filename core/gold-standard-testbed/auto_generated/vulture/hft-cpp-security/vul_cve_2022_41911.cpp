// Vulnerable: VUL-CVE-2022-41911
#include "tensorflow/core/framework/tensor.h"

#include <utility>

...

template <typename T>
string SummarizeArray(int64_t limit, int64_t num_elts,
                      const TensorShape& tensor_shape, const char* data,
                      const bool print_v2) {
  string ret;
...
  return ret;
}
}  // namespace
