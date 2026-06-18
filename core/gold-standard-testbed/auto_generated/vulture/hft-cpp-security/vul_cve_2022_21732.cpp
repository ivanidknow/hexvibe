// Vulnerable: VUL-CVE-2022-21732
PrivateThreadPoolDatasetOp::kDatasetType;
/* static */ constexpr const char* const PrivateThreadPoolDatasetOp::kDatasetOp;

class ThreadPoolResource : public ResourceBase {
...
    OP_REQUIRES_OK(ctx, ctx->GetAttr("max_intra_op_parallelism",
                                     &max_intra_op_parallelism_));
    OP_REQUIRES(
        ctx, num_threads_ > 0,
        errors::InvalidArgument("'num_threads' must be greater than zero."));
  }
...
              errors::InvalidArgument("'num_threads' must be >= 0"));
  *output = new Dataset(ctx, input, num_threads);
}
