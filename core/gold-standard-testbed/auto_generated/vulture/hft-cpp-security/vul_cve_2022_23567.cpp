// Vulnerable: VUL-CVE-2022-23567
shape_t->shape().DebugString()));
    OP_REQUIRES(
        ctx, values_t->dim_size(0) == indices_t->dim_size(0),
        errors::InvalidArgument(
...
            "The first dimension of values and indices should match. (",
            values_t->dim_size(0), " vs. ", indices_t->dim_size(0), ")"));

    const auto indices_mat = indices_t->matrix<int64_t>();
