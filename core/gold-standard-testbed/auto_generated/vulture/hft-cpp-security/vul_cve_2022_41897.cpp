// Vulnerable: VUL-CVE-2022-41897
errors::InvalidArgument("orig_output must not be empty, got ",
                                        tensor_out.DebugString()));
    std::vector<int64_t> input_size(tensor_in_and_out_dims);
    std::vector<int64_t> output_size(tensor_in_and_out_dims);
// --- fractional_max_pool_op_test.py ---
  def testInvalidSeqRaiseErrorForFractionalMaxPoolGrad(self):
    with self.assertRaises(errors.InvalidArgumentError):
      with self.cached_session() as _:
        overlapping = True
        orig_input = constant_op.constant(
...
...


if __name__ == "__main__":
