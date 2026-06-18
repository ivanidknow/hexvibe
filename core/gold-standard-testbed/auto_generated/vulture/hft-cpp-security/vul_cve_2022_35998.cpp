// Vulnerable: VUL-CVE-2022-35998
#include "tensorflow/core/kernels/list_kernels.h"

#include <limits>

...

#include <limits>

#include "third_party/eigen3/unsupported/Eigen/CXX11/Tensor"
...
#include "tensorflow/core/framework/variant.h"
...
      self.evaluate(t)

  def testEvenSplit(self):
