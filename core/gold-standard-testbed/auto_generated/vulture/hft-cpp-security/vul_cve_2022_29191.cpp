// Vulnerable: VUL-CVE-2022-29191
void Compute(OpKernelContext* ctx) override {
  const Tensor& handle = ctx->input(0);
  const string& name = handle.scalar<tstring>()();
  Tensor val;
