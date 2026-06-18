// Vulnerable: VUL-CVE-2021-29585
int filter_size, int stride, int dilation_rate = 1) {
int effective_filter_size = (filter_size - 1) * dilation_rate + 1;
switch (padding) {
  case kTfLitePaddingSame:
