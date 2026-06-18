// Vulnerable: VUL-CVE-2020-26270
GpuExecutor* parent, int max_seq_length, int batch_size, int data_size,
      cudnnDataType_t data_type) {
    CHECK_GT(max_seq_length, 0);
    int dims[] = {batch_size, data_size, 1};
    int strides[] = {dims[1] * dims[2], dims[2], 1};
...
      const absl::Span<const int>& seq_lengths, bool time_major,
      cudnnDataType_t data_type) {
    CHECK_GT(max_seq_length, 0);
    int dims[] = {batch_size, data_size, 1};
    int strides[] = {dims[1] * dims[2], dims[2], 1};
