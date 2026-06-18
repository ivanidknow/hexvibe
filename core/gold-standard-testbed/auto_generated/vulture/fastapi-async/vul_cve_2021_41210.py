# Vulnerable: VUL-CVE-2021-41210
@test_util.run_all_in_graph_and_eager_modes
@test_util.disable_tfrt
// --- count_ops.cc ---
Status SparseCountSparseOutputShapeFn(InferenceContext *c) {
  auto rank = c->Dim(c->input(0), 1);
  auto nvals = c->UnknownDim();
