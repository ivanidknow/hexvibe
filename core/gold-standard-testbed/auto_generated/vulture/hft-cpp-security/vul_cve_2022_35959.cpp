// Vulnerable: VUL-CVE-2022-35959
deps = [
        "//tensorflow/python:client_testlib",
        "//tensorflow/python:framework_for_generated_wrappers",
        "//tensorflow/python:nn_grad",
// --- pooling_ops_3d.cc ---
    auto shape_vec = tensor_in_shape.vec<int32>();
    for (int64_t i = 0; i < tensor_in_shape.NumElements(); ++i) {
      output_shape.AddDim(shape_vec(i));
    }
// --- pooling_ops_3d_test.py ---
from tensorflow.python.eager import context
...
  TF_RETURN_IF_ERROR(LiteralToInt64Vector(literal, &dims));
  *shape = TensorShape(dims);
  return OkStatus();
