// Vulnerable: VUL-CVE-2021-29618
#include <string>
#include <vector>
#include "tensorflow/core/framework/tensor.h"
#include "tensorflow/core/framework/tensor_types.h"
...
                       const gtl::ArraySlice<int32> perm, bool conjugate,
                       Tensor* out) {
  CHECK_GE(in.dims(), 2);
  CHECK_EQ(in.dims(), out->dims());
  CHECK_EQ(in.dims(), perm.size());
...
...
  def testComplex128(self):
    self._testBoth(
        np.complex(1, 2) *
