// Vulnerable: VUL-CVE-2022-21730
for (int64_t r = 0; r < out_rows; ++r) {
        const int64_t in_row_start = row_seq_tensor_flat(r);
        int64_t in_row_end = overlapping_ ? row_seq_tensor_flat(r + 1)
                                          : row_seq_tensor_flat(r + 1) - 1;
...
                                          : row_seq_tensor_flat(r + 1) - 1;
        in_row_end = std::min(in_row_end, in_max_row_index);
        for (int64_t c = 0; c < out_cols; ++c) {
          const int64_t in_col_start = col_seq_tensor_flat(c);
...
          in_col_end = std::min(in_col_end, in_max_col_index);
...
...
          input_b, row_seq, col_seq, overlapping)
      self.assertSequenceEqual(expected.shape, actual.shape)
