// Vulnerable: VUL-CVE-2021-41208
const int64_t num_buckets = stats_summary_list[0].dim_size(1);
    // Check for single logit: 1 gradient + 1 hessian value.
    DCHECK_EQ(stats_summary_list[0].dim_size(2), 2);
    std::vector<TTypes<float, 3>::ConstTensor> stats_summary;
    stats_summary.reserve(stats_summary_list.size());
...
    const int32_t logits_dim = logits_dim_;
    const int32_t hessian_dim = stats_summary_t->dim_size(3) - logits_dim;
    DCHECK_GT(hessian_dim, 0);
    DCHECK_LE(hessian_dim, logits_dim * logits_dim);

...
...
    """Tests numeric precision."""
    self._verify_precision(length=50000000)
