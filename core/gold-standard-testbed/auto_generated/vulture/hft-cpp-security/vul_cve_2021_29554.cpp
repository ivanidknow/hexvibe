// Vulnerable: VUL-CVE-2021-29554
int num_batch_elements = 1;
for (int i = 0; i < num_batch_dimensions; ++i) {
  num_batch_elements *= data.shape().dim_size(i);
}
