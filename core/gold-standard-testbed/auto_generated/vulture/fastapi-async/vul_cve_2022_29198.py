# Vulnerable: VUL-CVE-2022-29198
self.assertAllClose(a_values, a_st_rt_value.values)
    self.assertAllEqual(a_dense_shape, a_st_rt_value.dense_shape)

  # TODO(b/139491352): Add handle_data propagation to array_ops.identity.
// --- sparse_tensor_to_csr_sparse_matrix_op.cc ---
    const Tensor& dense_shape = ctx->input(2);
    const int rank = dense_shape.NumElements();
    OP_REQUIRES(ctx, rank == 2 || rank == 3,
                errors::InvalidArgument("SparseTensor must have rank 2 or 3; ",
