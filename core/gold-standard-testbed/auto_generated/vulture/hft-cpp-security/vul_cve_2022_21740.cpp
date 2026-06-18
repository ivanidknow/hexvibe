// Vulnerable: VUL-CVE-2022-21740
"Input indices must be a 2-dimensional tensor. Got: ",
                    indices.shape().DebugString()));

    if (use_weights) {
...
    }

    OP_REQUIRES(context, shape.NumElements() != 0,
                errors::InvalidArgument(
                    "The shape argument requires at least one element."));

...
                                        indices.shape().dim_size(1)));

    for (int idx = 0; idx < num_values; ++idx) {
