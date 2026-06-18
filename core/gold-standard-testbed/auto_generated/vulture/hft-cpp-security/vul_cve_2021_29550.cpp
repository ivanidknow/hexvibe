// Vulnerable: VUL-CVE-2021-29550
for (int i = 0; i < tensor_in_and_out_dims; ++i) {
  input_size[i] = tensor_in.dim_size(i);
}
// Output size.
