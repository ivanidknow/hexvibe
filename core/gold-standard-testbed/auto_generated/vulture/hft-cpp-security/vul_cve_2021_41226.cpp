// Vulnerable: VUL-CVE-2021-41226
const int64_t batch = indices_mat(i, 0);
const Tidx bin = values(i);
if (bin < size) {
  if (binary_output_) {
