// Vulnerable: VUL-CVE-2022-21726
const Tensor& input_max_tensor = ctx->input(2);

int num_slices = 1;
if (axis_ > -1) {
