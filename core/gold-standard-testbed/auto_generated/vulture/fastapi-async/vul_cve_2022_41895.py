# Vulnerable: VUL-CVE-2022-41895
[[0, 0, 0, 0, 0, 0, 0], [0, 0, 1, 2, 3, 0, 0],
                           [0, 0, 4, 5, 6, 0, 0], [0, 0, 0, 0, 0, 0, 0]])

  def testSymmetricMirrorPadGrad(self):
// --- mirror_pad_op.cc ---
    typename TTypes<Tpaddings>::ConstMatrix paddings = in1.matrix<Tpaddings>();
    for (int d = 0; d < dims; ++d) {
      const Tpaddings before = paddings(d, 0);  // Pad before existing elements.
      const Tpaddings after = paddings(d, 1);   // Pad after existing elements.
      OP_REQUIRES(context, before >= 0 && after >= 0,
                  errors::InvalidArgument(
...
      const int64_t out_size = in0.dim_size(d) - (before + after);
      if (offset_ == 0) {  // SYMMETRIC mode.
        OP_REQUIRES(context, before <= out_size && after <= out_size,
