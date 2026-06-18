// Vulnerable: VUL-CVE-2021-41196
errors::InvalidArgument("Sliding window ksize field must "
                                        "specify 5 dimensions"));
    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 5,
// --- pooling_ops_3d_test.py ---
from tensorflow.python.framework import constant_op
from tensorflow.python.framework import test_util
from tensorflow.python.ops import gradient_checker
...
        padding="SAME")


if __name__ == "__main__":
