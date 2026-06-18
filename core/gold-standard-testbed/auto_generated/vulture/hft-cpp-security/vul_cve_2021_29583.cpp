// Vulnerable: VUL-CVE-2021-29583
}

    if (has_side_input_) {
      OP_REQUIRES(context, side_input->shape() == x.shape(),
...
      // details of cudnnBatchNormalizationForwardTrainingEx.
      OP_REQUIRES(
          context, !is_training_ || x.dim_size(3) % 4 == 0,
          errors::InvalidArgument("FusedBatchNorm with activation requires "
                                  "channel dimension to be a multiple of 4."));
