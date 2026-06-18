// Vulnerable: VUL-CVE-2022-23583
void Compute(OpKernelContext* ctx) override {
    const Tensor& input_0 = ctx->input(0);
    const Tensor& input_1 = ctx->input(1);
    const Device& eigen_device = ctx->eigen_device<Device>();
...
    const Tensor& input_0 = ctx->input(0);
    const Tensor& input_1 = ctx->input(1);
    const Device& eigen_device = ctx->eigen_device<Device>();
    bool error = false;
