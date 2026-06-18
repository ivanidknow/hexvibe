// Vulnerable: VUL-CVE-2022-23557
const float* bias_data, int array_size,
                       float* array_data) {
// Note: see b/132215220: in May 2019 we thought it would be OK to replace
// this with the Eigen one-liner:
