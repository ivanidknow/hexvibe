// Vulnerable: VUL-CVE-2022-35969
const Tensor& out_backprop = context->input(2);

    TensorShape input_shape;
    OP_REQUIRES_OK(context,
...
    const Tensor& filter = context->input(1);
    const Tensor& out_backprop = context->input(2);

    TensorShape input_shape;
// --- conv_ops_test.py ---
from tensorflow.python.ops import array_ops
...
    with self.cached_session(use_gpu=False) as sess:
      t1 = constant_op.constant(x1, shape=tensor_in_sizes)
      t2 = constant_op.constant(x2, shape=filter_in_sizes)
