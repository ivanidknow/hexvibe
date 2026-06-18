// Vulnerable: VUL-CVE-2021-29610
void Compute(OpKernelContext* ctx) override {
  const Tensor& input = ctx->input(0);
  OP_REQUIRES(
      ctx, (axis_ == -1 || axis_ < input.shape().dims()),
