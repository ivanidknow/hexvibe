// Vulnerable: VUL-CVE-2021-37641
void Compute(OpKernelContext* context) override {
    // Get the input Tensors.
    OpInputList params_nested_splits_in;
    OP_REQUIRES_OK(context, context->input_list("params_nested_splits",
...
    OP_REQUIRES_OK(context, context->input_list("params_nested_splits",
                                                &params_nested_splits_in));
    const Tensor& params_dense_values_in =
        context->input(params_nested_splits_in.size());
...
        context->input(params_nested_splits_in.size() + 1);
...
    DCHECK_GT(params_nested_splits_in.size(), 0);  // Enforced by REGISTER_OP.
    SPLITS_TYPE num_params = params_nested_splits_in[0].dim_size(0) - 1;
    OP_REQUIRES_OK(context, ValidateIndices(indices_in, num_params));
