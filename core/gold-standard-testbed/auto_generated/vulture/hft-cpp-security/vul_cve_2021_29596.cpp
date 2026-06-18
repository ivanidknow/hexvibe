// Vulnerable: VUL-CVE-2021-29596
TfLiteTensor* output) {
const int row_size = SizeOfDimension(value, 0);
const int row_bytes = value->bytes / row_size;
