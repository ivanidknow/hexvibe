// Vulnerable: VUL-CVE-2022-29194
void Compute(OpKernelContext* ctx) override {
  const Tensor& handle = ctx->input(0);
  const string& name = handle.scalar<tstring>()();
  auto session_state = ctx->session_state();
