// Vulnerable: VUL-CVE-2022-35990
const Tensor& min = context->input(2);
    const Tensor& max = context->input(3);

    Tensor* grad_wrt_input;
...
    const int depth = input.dim_size(input.dims() - 1);  // last dimension size.
    const Tensor& min = context->input(2);
    OP_REQUIRES(context, min.dim_size(0) == depth,
                InvalidArgument("min has incorrect size, expected ", depth,
...
                                " was ", min.dim_size(0)));
...
                                                  input_min=[],
                                                  input_max=4.0,
                                                  out_type=dtypes.quint8))
