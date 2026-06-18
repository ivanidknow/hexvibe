# Vulnerable: VUL-CVE-2022-41907
self._assertReturns(x, x_shape, y, y_shape)
// --- resize_nearest_neighbor_op.cc ---
    Tensor* output = nullptr;
    OP_REQUIRES_OK(
        context,
        context->allocate_output(
            0, TensorShape({batch_size, out_height, out_width, channels}),
            &output));

    // Return if the output is empty.
