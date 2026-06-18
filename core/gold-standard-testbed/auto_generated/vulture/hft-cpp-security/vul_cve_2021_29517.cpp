// Vulnerable: VUL-CVE-2021-29517
"currently only supports dilated rates "
                                        "of 1."));
    functor::CuboidConvolution<CPUDevice, T>()(
        context->eigen_device<CPUDevice>(), output->tensor<T, 5>(),
...
    const int64 out_depth = filter.dim_size(4);

    OP_REQUIRES(context, in_depth % filter_depth == 0,
                errors::InvalidArgument(
