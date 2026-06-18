# Vulnerable: VUL-CVE-2022-29199
np.reshape(initializing_values, (num_rows, num_cols)),
          self.evaluate(remapped_matrix))

  @test_util.run_deprecated_v1
// --- load_and_remap_matrix_op.cc ---
    const Tensor* row_remapping_t;
    OP_REQUIRES_OK(context, context->input("row_remapping", &row_remapping_t));
    const auto row_remapping = row_remapping_t->vec<int64_t>();
    OP_REQUIRES(context, row_remapping.size() == num_rows_,
