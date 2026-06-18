// Vulnerable: VUL-CVE-2022-35996
#include "tensorflow/core/kernels/conv_2d.h"
#include "tensorflow/core/kernels/deep_conv2d.h"
#include "tensorflow/core/kernels/ops_util.h"
#include "tensorflow/core/lib/core/errors.h"
...
    // If there is nothing to compute, return.
    if (out_shape.num_elements() == 0) {
      return;
    }
// --- conv_ops_test.py ---
        dilations=[2, 3])

  def testConv2DExplicitPaddingWithLayoutOptimizer(self):
    # Test with Grappler's layout optimizer, to ensure the layout optimizer
