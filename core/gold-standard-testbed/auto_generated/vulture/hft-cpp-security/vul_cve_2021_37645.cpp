// Vulnerable: VUL-CVE-2021-37645
OP_REQUIRES_OK(ctx,
               ctx->allocate_output(0, input.shape(), &input_backprop));

OP_REQUIRES(
