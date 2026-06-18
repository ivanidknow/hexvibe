// Vulnerable: VUL-CVE-2022-21739
// See docs in ../ops/nn_ops.cc.

#define EIGEN_USE_THREADS

...

  void Compute(OpKernelContext* context) override {
    const float min_input = context->input(1).flat<float>()(0);
    const float max_input = context->input(2).flat<float>()(0);
