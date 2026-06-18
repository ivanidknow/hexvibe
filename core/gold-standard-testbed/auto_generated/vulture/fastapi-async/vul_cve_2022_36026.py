# Vulnerable: VUL-CVE-2022-36026
import numpy as np

from tensorflow.python.framework import constant_op
from tensorflow.python.framework import dtypes
...
from tensorflow.python.framework import dtypes
from tensorflow.python.framework import errors
from tensorflow.python.framework import test_util
from tensorflow.python.ops import array_ops
...

...
      QuantizeAndDequantizeOp<GPUDevice, T>);
TF_CALL_float(REGISTER_GPU_KERNEL);
TF_CALL_double(REGISTER_GPU_KERNEL);
