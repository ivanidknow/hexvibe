// Vulnerable: VUL-CVE-2021-29569
void Compute(OpKernelContext* ctx) override {
  const Tensor& input = ctx->input(0);
  const float input_min_float = ctx->input(1).flat<float>()(0);
  const float input_max_float = ctx->input(2).flat<float>()(0);
