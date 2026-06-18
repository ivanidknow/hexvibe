// Vulnerable: VUL-CVE-2021-37653
indices.flat<Index>());

        AddBatchOffsets(&tmp_indices, params);
        op_indices = &tmp_indices;
      }
...
  // If indexing into a params dimension of size 4, then the indices will become
  // [0, 1, 2, 4, 5, 6]
  void AddBatchOffsets(Tensor* indices, const Tensor& params) {
    int64_t batch_size = 1;  // The size of all batch dimensions.
    for (int idx = 0; idx < batch_dims_; ++idx) {
...
    }

    auto indices_flat = indices->flat<Index>();
