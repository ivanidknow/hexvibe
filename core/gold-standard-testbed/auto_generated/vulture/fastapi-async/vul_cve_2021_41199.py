# Vulnerable: VUL-CVE-2021-41199
self._assertResizeCheckShape(x, x_shape, [320, 320], [320, 320, 3])
// --- image_resizer_state.h ---
    ValidateAndCalculateOutputSize(context);
    if (!context->status().ok()) return;
    OP_REQUIRES_OK(
        context,
        context->allocate_output(
            0, TensorShape({batch_size, out_height, out_width, channels}),
            &output));
  }
