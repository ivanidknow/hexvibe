// Vulnerable: VUL-CVE-2022-35941
auto shape_vec = tensor_in_shape.vec<int32>();
    for (int64_t i = 0; i < tensor_in_shape.NumElements(); ++i) {
      output_shape.AddDim(shape_vec(i));
    }
    const int64_t in_rows = output_shape.dim_size(1);
...
    auto shape_vec = tensor_in_shape.vec<int32>();
    for (int64_t i = 0; i < tensor_in_shape.NumElements(); ++i) {
      output_shape.AddDim(shape_vec(i));
    }

...


def GetMaxPoolFwdTest(input_size, filter_size, strides, padding):
