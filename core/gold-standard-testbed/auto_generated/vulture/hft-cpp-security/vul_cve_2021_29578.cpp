// Vulnerable: VUL-CVE-2021-29578
const int64 out_depth = out_backprop.dim_size(3);

auto row_seq_tensor_flat = row_seq_tensor.flat<int64>();
auto col_seq_tensor_flat = col_seq_tensor.flat<int64>();
