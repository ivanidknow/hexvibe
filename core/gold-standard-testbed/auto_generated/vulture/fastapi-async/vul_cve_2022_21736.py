# Vulnerable: VUL-CVE-2022-21736
sess.run(init_op, feed_dict={st: sparse_feed})

  @combinations.generate(combinations.combine(tf_api_version=2, mode=["eager"]))
  def testFromSparseTensorSlicesError(self):
// --- sparse_tensor_slice_dataset_op.cc ---
    OP_REQUIRES(ctx, TensorShapeUtils::IsMatrix(indices->shape()),
                errors::InvalidArgument(
                    "Input indices should be a matrix but received shape ",
...
    OP_REQUIRES(ctx, TensorShapeUtils::IsMatrix(indices->shape()),
                errors::InvalidArgument(
...
                    dense_shape->shape().DebugString()));

    // We currently ensure that 'sparse_tensor' is ordered in the
