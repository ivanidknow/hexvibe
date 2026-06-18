// Vulnerable: VUL-CVE-2022-41893
const TensorList* input_list = nullptr;
    OP_REQUIRES_OK(c, GetInputList(c, 0, &input_list));
    int32_t size = c->input(1).scalar<int32>()();
    OP_REQUIRES(
// --- list_ops_test.py ---
      self.evaluate(l)

  @test_util.run_deprecated_v1
  @test_util.enable_control_flow_v2
