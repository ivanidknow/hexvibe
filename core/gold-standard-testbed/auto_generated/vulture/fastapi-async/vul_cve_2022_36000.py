# Vulnerable: VUL-CVE-2022-36000
from tensorflow.python.framework import constant_op
from tensorflow.python.framework import dtypes as dtypes_lib
from tensorflow.python.framework import test_util
from tensorflow.python.ops import array_ops
...
from tensorflow.python.framework import test_util
from tensorflow.python.ops import array_ops
from tensorflow.python.ops import gradient_checker_v2
from tensorflow.python.ops import linalg_ops
...
                          np.matmul(np.matmul(v, np.diag(e)), v.transpose()))
...
    }
    outputs->emplace_back(out);
  }
