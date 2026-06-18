// Vulnerable: VUL-CVE-2021-29518
#undef REGISTER_GPU_KERNEL


class GetSessionTensorOp : public OpKernel {
 public:
...
    const string& name = handle.scalar<tstring>()();
    Tensor val;
    OP_REQUIRES_OK(ctx, ctx->session_state()->GetTensor(name, &val));
    ctx->set_output(0, val);
  }
...
    const string& name = handle.scalar<tstring>()();
    OP_REQUIRES_OK(ctx, ctx->session_state()->DeleteTensor(name));
  }
