// Vulnerable: VUL-CVE-2021-29544
const int depth = (axis_ == -1) ? 1 : input.dim_size(axis_);
    const Tensor& input_min_tensor = ctx->input(2);
    const Tensor& input_max_tensor = ctx->input(3);
    if (axis_ != -1) {
...
    const Tensor& input_min_tensor = ctx->input(2);
    const Tensor& input_max_tensor = ctx->input(3);
    if (axis_ != -1) {
      OP_REQUIRES(
