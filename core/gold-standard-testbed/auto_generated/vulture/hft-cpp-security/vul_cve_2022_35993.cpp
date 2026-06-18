// Vulnerable: VUL-CVE-2022-35993
// Assume row-major order.
  TensorShape shape;
  TF_RETURN_IF_ERROR(TensorShape::BuildTensorShape(
      ctx->input(base_index + 2).vec<int64_t>(), &shape));
  CheckRankAtLeast2(ctx, shape);
  std::vector<int64_t> order(shape.dims());
// --- sets_test.py ---
from tensorflow.python.framework import test_util
from tensorflow.python.ops import array_ops
from tensorflow.python.ops import math_ops
from tensorflow.python.ops import sets
...


if __name__ == "__main__":
