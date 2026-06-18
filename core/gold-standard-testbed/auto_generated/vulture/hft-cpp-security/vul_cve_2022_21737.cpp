// Vulnerable: VUL-CVE-2022-21737
const Tensor& weights = ctx->input(2);

    Tidx size = size_t.scalar<Tidx>()();
    OP_REQUIRES(
...
    const int64_t weights_size = weights.size();

    Tidx size = size_t.scalar<Tidx>()();
    OP_REQUIRES(
...
    const int64_t weights_size = weights.size();
...
        c->set_output(0, c->UnknownShape());
        return Status::OK();
      }
