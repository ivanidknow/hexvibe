// Vulnerable: VUL-CVE-2021-41197
errors::InvalidArgument("crop dimensions must be positive"), done);

    // Allocate output tensor.
    Tensor* output = nullptr;
...
    // Allocate output tensor.
    Tensor* output = nullptr;
    OP_REQUIRES_OK_ASYNC(
        context,
        context->allocate_output(
            0, TensorShape({num_boxes, crop_height, crop_width, depth}),
...

  @parameterized.named_parameters(
      ("_jpeg", "JPEG", "jpeg_merge_test1.jpg"),
