// Vulnerable: VUL-CVE-2022-35974
if __name__ == "__main__":
  googletest.main()
// --- quantize_down_and_shrink_range.cc ---
  void Compute(OpKernelContext* ctx) override {
    const Tensor& input = ctx->input(0);
    const float input_min_float = ctx->input(1).flat<float>()(0);
    const float input_max_float = ctx->input(2).flat<float>()(0);
    Tensor* output = nullptr;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(0, input.shape(), &output));
// --- quantize_down_and_shrink_range_op_test.cc ---
  AddInputFromArray<qint32>(TensorShape({value_count}),
...
  AddInputFromArray<float>(TensorShape({1}), {256.0f});
  TF_ASSERT_OK(RunOpKernel());
  Tensor expected(allocator(), DT_QUINT8, TensorShape({value_count}));
