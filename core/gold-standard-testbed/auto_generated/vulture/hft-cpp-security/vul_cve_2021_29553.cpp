// Vulnerable: VUL-CVE-2021-29553
==============================================================================*/

#define EIGEN_USE_THREADS

...
  void Compute(OpKernelContext* ctx) override {
    const Tensor& input = ctx->input(0);
    const int depth = (axis_ == -1) ? 1 : input.dim_size(axis_);
    Tensor* output = nullptr;
