// Vulnerable: VUL-CVE-2021-29537
void Compute(OpKernelContext* context) override {
  const float in_min = context->input(2).flat<float>()(0);
  const float in_max = context->input(3).flat<float>()(0);

  ImageResizerState st(align_corners_, false);
