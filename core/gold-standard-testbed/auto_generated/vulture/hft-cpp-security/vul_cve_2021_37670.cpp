// Vulnerable: VUL-CVE-2021-37670
const Tensor& values_t = ctx->input(1);

    // must have same batch dim_size for both
    OP_REQUIRES(ctx, sorted_inputs_t.dim_size(0) == values_t.dim_size(0),
...
    const Tensor& values_t = ctx->input(1);

    // must have same batch dim_size for both
    OP_REQUIRES(ctx, sorted_inputs_t.dim_size(0) == values_t.dim_size(0),
