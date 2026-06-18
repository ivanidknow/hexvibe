// Vulnerable: VUL-CVE-2021-37673
OP_REQUIRES_OK(ctx, ctx->input("indices", &indices_tensor));
OP_REQUIRES_OK(ctx, ctx->input_list("values", &values_tensor));

// Create copy for insertion into Staging Area
