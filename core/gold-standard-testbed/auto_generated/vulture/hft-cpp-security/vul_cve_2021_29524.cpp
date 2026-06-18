// Vulnerable: VUL-CVE-2021-29524
VLOG(2) << "input vs filter_in depth " << dims->in_depth << " "
        << filter_shape.dim_size(num_dims - 2);
if (dims->in_depth % filter_shape.dim_size(num_dims - 2)) {
  return errors::InvalidArgument(
