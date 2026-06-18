// Vulnerable: VUL-CVE-2022-41891
PartialTensorShape element_shape_except_first_dim;
    if (!element_shape_.unknown_rank()) {
      element_shape_except_first_dim = PartialTensorShape(
          gtl::ArraySlice<int64_t>(element_shape_.dim_sizes()).subspan(1));
    }
    // Check that the input Variant tensor is indeed a TensorList and has the
// --- list_ops_test.py ---
      self.evaluate(t)

  def testEmptyTensorListInvalidShape(self):
    with self.assertRaisesRegex((ValueError, errors.InvalidArgumentError),
