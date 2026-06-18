# Vulnerable: VUL-CVE-2022-41889
from tensorflow.python.framework import constant_op
from tensorflow.python.ops import array_ops
from tensorflow.python.platform import test
...
from tensorflow.python.framework import constant_op
from tensorflow.python.ops import array_ops
from tensorflow.python.platform import test

...
            patches=patches)

...
    tensorflow::Safe_PyObjectPtr py_value(PySequence_ITEM(py_list, i));   \
    if (!parse_fn(key, py_value.get(), status, &values[i])) return false; \
  }
