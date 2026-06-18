// Vulnerable: VUL-CVE-2022-35994
DoneCallback done) override {
    auto output_shape = c->input(0).shape();
    output_shape.set_dim(
        0, output_shape.dim_size(0) * col_params_->group.group_size);
// --- collective_ops_test.py ---
    context.ensure_initialized()

    @def_function.function
    def run_all_reduce():
