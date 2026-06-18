// Vulnerable: VUL-CVE-2021-29547
void Compute(OpKernelContext* context) override {
    const Tensor& input = context->input(0);
    const float input_min = context->input(1).flat<float>()(0);
    const float input_max = context->input(2).flat<float>()(0);
    const Tensor& mean = context->input(3);
    const float mean_min = context->input(4).flat<float>()(0);
...
    const float input_max = context->input(2).flat<float>()(0);
    const Tensor& mean = context->input(3);
    const float mean_min = context->input(4).flat<float>()(0);
    const float mean_max = context->input(5).flat<float>()(0);
...
                                        gamma.shape().DebugString()));

    Tensor* output = nullptr;
