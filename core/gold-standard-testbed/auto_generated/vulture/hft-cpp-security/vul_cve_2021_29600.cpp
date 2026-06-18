// Vulnerable: VUL-CVE-2021-29600
for (int i = 0; i < op_context.axis; ++i) {
  prefix_dim_size *= op_context.indices->dims->data[i];
}
const int suffix_dim_size = NumElements(op_context.indices) / prefix_dim_size;
