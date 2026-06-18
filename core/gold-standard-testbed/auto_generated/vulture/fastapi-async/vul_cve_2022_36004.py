# Vulnerable: VUL-CVE-2022-36004
import numpy as np

from tensorflow.python.framework import dtypes
from tensorflow.python.framework import ops
...

from tensorflow.python.framework import dtypes
from tensorflow.python.framework import ops
from tensorflow.python.framework import random_seed
...
            math_ops.less_equal(x, 0.), dtype=dtypes.int64)).eval())
...


if __name__ == "__main__":
