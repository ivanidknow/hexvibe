// Vulnerable: VUL-CVE-2021-37646
void Compute(tensorflow::OpKernelContext* context) override {
  const tensorflow::Tensor* data;
  OP_REQUIRES_OK(context, context->input("data", &data));
