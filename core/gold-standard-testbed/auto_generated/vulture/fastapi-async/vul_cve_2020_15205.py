# Vulnerable: VUL-CVE-2020-15205
from __future__ import print_function

from tensorflow.python.eager import context
from tensorflow.python.framework import constant_op
...
from tensorflow.python.eager import context
from tensorflow.python.framework import constant_op
from tensorflow.python.framework import ops
from tensorflow.python.framework import test_util
...
from tensorflow.python.framework import test_util
...
    const auto& splits_vec = splits->flat<SPLITS_TYPE>();

    int num_batch_items = splits_vec.size() - 1;
