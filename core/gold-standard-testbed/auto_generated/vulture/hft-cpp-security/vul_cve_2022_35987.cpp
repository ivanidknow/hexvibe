// Vulnerable: VUL-CVE-2022-35987
errors::InvalidArgument("Shape must be rank 0 but is rank ",
                                        size_t.dims()));
    Tidx size = size_t.scalar<Tidx>()();
    OP_REQUIRES(
// --- bincount_op_test.py ---
from tensorflow.python.ops import bincount_ops
from tensorflow.python.ops import gen_math_ops
from tensorflow.python.ops import sparse_ops
from tensorflow.python.ops.ragged import ragged_factory_ops
...
      self.assertAllEqual(v2.get_shape().as_list(), [None])


class BincountOpTest(test_util.TensorFlowTestCase, parameterized.TestCase):
