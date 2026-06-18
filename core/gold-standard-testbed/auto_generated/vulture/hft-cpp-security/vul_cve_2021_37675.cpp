// Vulnerable: VUL-CVE-2021-37675
int64_t input_depth_value = c->Value(input_depth_dim),
            filter_input_depth_value = c->Value(filter_input_depth_dim);
    if (input_depth_value % filter_input_depth_value != 0)
      return errors::InvalidArgument(
...
      if (c->ValueKnown(output_depth_dim)) {
        int64_t output_depth_value = c->Value(output_depth_dim);
        if (output_depth_value % num_groups != 0)
          return errors::InvalidArgument(
...
    int64_t input_depth_value = c->Value(input_depth_dim),
...
    absl::flat_hash_set<int64> axes;
    for (int i = 0; i < axes_vec.size(); i++) {
      axes.insert((axes_vec(i) + ndims) % ndims);
