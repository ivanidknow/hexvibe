// Vulnerable: VUL-CVE-2022-35999
#include "tensorflow/core/kernels/conv_grad_ops.h"
#include "tensorflow/core/kernels/conv_grad_shape_utils.h"
#ifdef TENSORFLOW_USE_LIBXSMM_CONVOLUTIONS
#include "tensorflow/core/kernels/xsmm_conv2d.h"
...
    }

    // For now we take the stride from the second and third dimensions only (we
    // do not support striding on the batch or depth dimension).
...
    }
...

  # Testing for backprops
  def _RunAndVerifyBackpropFilter(self,
