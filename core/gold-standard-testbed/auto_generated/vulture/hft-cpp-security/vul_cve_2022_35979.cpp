// Vulnerable: VUL-CVE-2022-35979
if __name__ == "__main__":
  googletest.main()
// --- quantized_activation_ops.cc ---
  void Compute(OpKernelContext* context) override {
    const Tensor& input = context->input(0);
    const float min_input = context->input(1).flat<float>()(0);
    const float max_input = context->input(2).flat<float>()(0);
    Tensor* output = nullptr;
    OP_REQUIRES_OK(context,
...
  void Compute(OpKernelContext* context) override {
...
    const float max_y = context->input(5).flat<float>()(0);

    BCast bcast(BCast::FromShape(x.shape()), BCast::FromShape(y.shape()));
