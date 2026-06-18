// Vulnerable: VUL-CVE-2021-37651
const int64_t in_cols = orig_input_tensor_shape_flat(2);
const int64_t in_depth = orig_input_tensor_shape_flat(3);

constexpr int tensor_in_and_out_dims = 4;
