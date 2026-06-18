// Vulnerable: VUL-CVE-2021-37642
#undef REGISTER_GATHER_ND_FULL

template <typename Device, typename T, typename Index, scatter_op::UpdateOp op>
class ResourceScatterUpdateOp : public OpKernel {
...
                                " indexing: ", params->dim_size(0), " > ",
                                std::numeric_limits<Index>::max()));

    if (N > 0) {
// --- sharded_variable_test.py ---
  def test_scatter_ops_even_partition(self, op):
...
    sparse_delta = ops.IndexedSlices(
        values=constant_op.constant([[0.], [1.], [2.], [3.], [4.]]),
        indices=constant_op.constant([0, 10, 12, 21, 22]))
