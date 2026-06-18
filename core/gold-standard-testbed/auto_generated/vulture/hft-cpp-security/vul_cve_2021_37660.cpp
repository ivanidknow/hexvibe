// Vulnerable: VUL-CVE-2021-37660
Tensor y = x;  // This creates an alias intentionally.
// Skip processing if tensors are empty.
if (x.NumElements() > 0 || v.NumElements() > 0) {
  OP_REQUIRES_OK(ctx, DoCompute(ctx, i, v, &y));
}
