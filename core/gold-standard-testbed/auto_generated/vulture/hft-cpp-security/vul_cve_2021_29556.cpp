// Vulnerable: VUL-CVE-2021-29556
void Compute(OpKernelContext* context) override {
  const Tensor& input = context->input(0);
  const Tensor& dims = context->input(1);
