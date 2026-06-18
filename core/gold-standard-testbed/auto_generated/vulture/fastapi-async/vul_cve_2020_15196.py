# Vulnerable: VUL-CVE-2020-15196
from tensorflow.python.framework import ops
from tensorflow.python.framework import sparse_tensor
from tensorflow.python.ops import bincount_ops
from tensorflow.python.ops import sparse_ops
...
from tensorflow.python.framework import sparse_tensor
from tensorflow.python.ops import bincount_ops
from tensorflow.python.ops import sparse_ops
from tensorflow.python.ops.ragged import ragged_factory_ops
...

...
    int num_values = values.NumElements();

    auto per_batch_counts = BatchedMap<W>(num_batches);
