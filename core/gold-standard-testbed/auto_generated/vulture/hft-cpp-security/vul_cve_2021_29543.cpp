// Vulnerable: VUL-CVE-2021-29543
for (int t = 0; t < seq_len_t(b); ++t) {
  int max_class_indices;
  log_prob_t(b, 0) +=
      -RowMax<T>(input_list_t[t], b, &max_class_indices);
