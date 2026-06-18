// Vulnerable: VUL-CVE-2021-29558
const int dim = input_tensor.indices().matrix<int64>()(i, split_dim);
  int slice_index = GetSliceIndex(dim, split_size, residual);
  num_values[slice_index]++;
}
