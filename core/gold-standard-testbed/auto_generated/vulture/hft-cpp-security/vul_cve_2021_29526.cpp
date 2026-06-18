// Vulnerable: VUL-CVE-2021-29526
const int64 patch_depth = filter.dim_size(2);

    if (in_depth % patch_depth != 0) {
      ctx->SetStatus(errors::InvalidArgument(
...

    const int64 num_groups = in_depth / patch_depth;
    if (out_depth % num_groups != 0 || out_depth < num_groups) {
      ctx->SetStatus(errors::InvalidArgument(
...
  const int in_depth = static_cast<int>(in_depth_raw);
  const int patch_depth = static_cast<int>(patch_depth_raw);
  TF_REQUIRES(in_depth % patch_depth == 0,
              errors::InvalidArgument(
