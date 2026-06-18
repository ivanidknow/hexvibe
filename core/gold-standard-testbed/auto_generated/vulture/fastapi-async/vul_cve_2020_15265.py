# Vulnerable: VUL-CVE-2020-15265
self.assertAllClose(fake_quantized, expected)

  def testQuantizeDequantizeGrad(self):
    shape = (2, 2)
// --- quantize_and_dequantize_op.cc ---
  void Compute(OpKernelContext* ctx) override {
    const Tensor& input = ctx->input(0);
    const int depth = (axis_ == -1) ? 1 : input.dim_size(axis_);
    Tensor input_min_tensor;
