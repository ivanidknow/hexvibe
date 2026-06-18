// Vulnerable: VUL-CVE-2021-37655
} else {
  int64_t num_updates = updates.NumElements();
  OP_REQUIRES(c, num_updates % N == 0,
              errors::InvalidArgument(
                  "shape of indices (", indices.shape().DebugString(),
                  ") is not compatible with the shape of updates (",
                  updates.shape().DebugString(), ")"));
  auto updates_flat = updates.shaped<T, 2>({N, num_updates / N});
