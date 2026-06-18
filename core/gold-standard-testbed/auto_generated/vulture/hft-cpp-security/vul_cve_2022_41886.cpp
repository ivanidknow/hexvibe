// Vulnerable: VUL-CVE-2022-41886
Tensor* output_t;
  OP_REQUIRES_OK(
      ctx, ctx->allocate_output(0,
...
  Tensor* output_t;
  OP_REQUIRES_OK(
      ctx, ctx->allocate_output(0,
                                TensorShape({images_t.dim_size(0), out_height,
                                             out_width, images_t.dim_size(3)}),
                                &output_t));
  auto output = output_t->tensor<T, 4>();
...
// --- image_ops_test.py ---
            offset_width=1)
        self.evaluate(v)
