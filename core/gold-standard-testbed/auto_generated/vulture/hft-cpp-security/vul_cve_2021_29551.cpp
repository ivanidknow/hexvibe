// Vulnerable: VUL-CVE-2021-29551
ValidateInputTensors(ctx, in0, in1);

    MatMulBCast bcast(in0.shape().dim_sizes(), in1.shape().dim_sizes());
...
  void ValidateInputTensors(OpKernelContext* ctx, const Tensor& in0,
                            const Tensor& in1) override {
    OP_REQUIRES(
        ctx, in0.dims() >= 2,
...
                            const Tensor& in1) override {
    OP_REQUIRES(
...
        errors::InvalidArgument("In[0] ndims must be >= 2: ", in1.dims()));
  }
};
