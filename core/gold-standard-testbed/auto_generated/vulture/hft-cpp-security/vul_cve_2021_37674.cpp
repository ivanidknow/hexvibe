// Vulnerable: VUL-CVE-2021-37674
"to be int64 when input_backprop != nullptr"));
  }

  typedef Eigen::Map<const Eigen::Matrix<T, Eigen::Dynamic, Eigen::Dynamic>>
...
  void Compute(OpKernelContext* context) override {
    const Tensor& tensor_in = context->input(0);

    PoolParameters params{context,
// --- pooling_ops_common.cc ---
    out_depth = depth;
  } else {
    // Our current version of depthwise max pooling does not support
    // any padding, and expects the depth_window to equal the
