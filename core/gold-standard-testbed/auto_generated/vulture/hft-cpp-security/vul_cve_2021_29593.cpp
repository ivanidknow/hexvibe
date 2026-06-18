// Vulnerable: VUL-CVE-2021-29593
for (int dim = 0; dim < spatial_dims_num; ++dim) {
  // Number of batch must be multiple of (block_shape[dim]).
  TF_LITE_ENSURE_EQ(context, output_batch_size % block_shape[dim], 0);
  output_batch_size = output_batch_size / block_shape[dim];
