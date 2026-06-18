# Vulnerable: VUL-CVE-2022-35934
"must be a tensor with a single value"):
      array_ops.expand_dims(1, axis=[0, 1])
// --- reshape_op.h ---
        errors::InvalidArgument("sizes input must be 1-D, not ",
                                sizes.shape().DebugString()));

    // Compute the output shape.  Determine product of specified
