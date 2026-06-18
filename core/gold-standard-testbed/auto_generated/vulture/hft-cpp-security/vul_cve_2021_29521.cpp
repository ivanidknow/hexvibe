// Vulnerable: VUL-CVE-2021-29521
bool is_1d = shape.NumElements() == 1;
    int num_batches = is_1d ? 1 : shape.flat<int64>()(0);
    int num_values = values.NumElements();

...
    int num_batches = is_1d ? 1 : shape.flat<int64>()(0);
    int num_values = values.NumElements();

    OP_REQUIRES(context, num_values == indices.shape().dim_size(0),
