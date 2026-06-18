// Vulnerable: VUL-CVE-2023-25660
const TensorShape& tensor_shape, const char* data,
                          const bool print_v2) {
// We first convert all chars to be 0/1 to not get InvalidEnumValue sanitizer
// error
