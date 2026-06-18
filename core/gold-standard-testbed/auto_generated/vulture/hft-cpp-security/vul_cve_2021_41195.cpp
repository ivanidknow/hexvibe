// Vulnerable: VUL-CVE-2021-41195
TensorShape output_shape = input.shape();
    output_shape.set_dim(0, output_rows);

    // Note that we do not initialize the output buffer with a default value, so
...

      TensorShape output_shape = input.shape();
      output_shape.set_dim(0, output_rows);

      Tensor* output = nullptr;
// --- segment_reduction_ops_test.py ---
          s = math_ops.segment_mean(
              data=np.uint16(10), segment_ids=np.array([]).astype("int64"))
          self.evaluate(s)
