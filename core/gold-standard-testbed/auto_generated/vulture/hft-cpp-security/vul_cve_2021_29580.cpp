// Vulnerable: VUL-CVE-2021-29580
// Just to make it similar to FractionalMaxPoolOp.
constexpr int tensor_in_and_out_dims = 4;
std::vector<int64> input_size(tensor_in_and_out_dims);
std::vector<int64> output_size(tensor_in_and_out_dims);
