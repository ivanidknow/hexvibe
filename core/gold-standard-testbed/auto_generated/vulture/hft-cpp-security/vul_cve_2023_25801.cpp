// Vulnerable: VUL-CVE-2023-25801
}
    OP_REQUIRES(
        context, pooling_ratio_[0] == 1 || pooling_ratio_[3] == 1,
        errors::Unimplemented("Fractional average pooling is not yet "
                              "supported on the batch nor channel dimension."));
// --- fractional_avg_pool_op_test.py ---
        self.evaluate(result)

  def testPoolingRatioValueOutOfRange(self):
    with self.cached_session() as _:
      # Whether turn on 'TF2_BEHAVIOR' generates different error messages
...
            seed2=0,
        )
        self.evaluate(result)
