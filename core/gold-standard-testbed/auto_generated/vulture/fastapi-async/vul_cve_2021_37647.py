# Vulnerable: VUL-CVE-2021-37647
sess.run(get_next)

  @combinations.generate(combinations.combine(tf_api_version=2, mode=["eager"]))
  def testFromSparseTensorSlicesError(self):
// --- sparse_tensor_slice_dataset_op.cc ---
                    "Input indices should be a matrix but received shape ",
                    indices->shape().DebugString()));
    OP_REQUIRES(ctx, TensorShapeUtils::IsVector(values->shape()),
                errors::InvalidArgument(
