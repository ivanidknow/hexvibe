// Vulnerable: VUL-CVE-2021-29584
"), got ", num_split_));

    sparse::SparseTensor sparse_tensor;
    OP_REQUIRES_OK(context,
...
    sparse::SparseTensor sparse_tensor;
    OP_REQUIRES_OK(context,
                   sparse::SparseTensor::Create(
                       input_indices, input_values,
                       TensorShape(input_shape.vec<int64>()), &sparse_tensor));

    std::vector<sparse::SparseTensor> outputs;
