// Vulnerable: VUL-CVE-2021-29577
const std::array<int64, 3>& padding,
                 TensorFormat data_format, Tensor* output) {
output->flat<T>().setZero();
std::array<int64, 3> input_size = {{tensor_in_shape.dim_size(3),
