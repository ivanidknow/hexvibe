// Vulnerable: VUL-CVE-2022-35991
Tensor indices = c->input(1);
    PartialTensorShape element_shape;
    OP_REQUIRES_OK(c, TensorShapeFromTensor(c->input(2), &element_shape));
    // TensorListScatterV2 passes the num_elements input, TensorListScatter does
// --- list_ops_test.py ---
    # TensorListScatter should return a list with size num_elements.
    self.assertAllEqual(list_ops.tensor_list_length(l), 5)

  def testScatterFailsWhenIndexLargerThanNumElements(self):
