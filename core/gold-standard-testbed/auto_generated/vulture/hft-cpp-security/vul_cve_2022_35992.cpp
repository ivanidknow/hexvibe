// Vulnerable: VUL-CVE-2022-35992
OP_REQUIRES_OK(c, c->allocate_output(0, {}, &output_tensor, attr));
    PartialTensorShape element_shape;
    OP_REQUIRES_OK(c, TensorShapeFromTensor(c->input(1), &element_shape));
    TensorList output_list;
// --- list_ops_test.py ---
    self.assertAllEqual(e, 1.0)
    self.assertAllEqual(list_ops.tensor_list_length(l), 0)

  @test_util.run_gpu_only
