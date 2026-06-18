// Vulnerable: VUL-CVE-2021-29564
"truth_shape should be a vector, but got shape: ",
        truth_shape.shape().DebugString());
  if (hypothesis_shape.NumElements() != hypothesis_indices.dim_size(1))
    return errors::InvalidArgument(
...
        "rank is: ",
        truth_shape.NumElements());
  if (truth_shape.NumElements() != truth_indices.dim_size(1))
    return errors::InvalidArgument(
...
                                   truth_st_shape.dim_size(d)));
...
                                    output_strides.begin(), int64{0});
      output_t(loc) = (normalize_) ? 1.0 : truth_seq.size();
      ++truth_iter;
