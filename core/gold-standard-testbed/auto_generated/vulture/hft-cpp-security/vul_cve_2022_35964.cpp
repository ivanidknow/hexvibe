// Vulnerable: VUL-CVE-2022-35964
const Tensor* x;
    OP_REQUIRES_OK(ctx, ctx->input("x", &x));
    OP_REQUIRES(ctx, x->dims() == 3, errors::InvalidArgument("x must be 3D"));
    const int64_t timelen = x->dim_size(0);
    const int64_t batch_size = x->dim_size(1);
...
    const Tensor* cs_prev_tensor = nullptr;
    OP_REQUIRES_OK(ctx, ctx->input("cs_prev", &cs_prev_tensor));

    const Tensor* h_prev_tensor = nullptr;
...
...


class BidirectionalRNNTest(test.TestCase):
