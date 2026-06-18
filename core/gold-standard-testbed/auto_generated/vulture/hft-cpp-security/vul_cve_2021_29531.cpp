// Vulnerable: VUL-CVE-2021-29531
errors::InvalidArgument("image must be 3-dimensional",
                                    image.shape().DebugString()));
OP_REQUIRES(
    context,
