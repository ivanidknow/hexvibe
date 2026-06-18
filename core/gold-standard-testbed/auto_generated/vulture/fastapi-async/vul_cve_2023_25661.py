# Vulnerable: VUL-CVE-2023-25661
f_value = np.random.random_sample(f_shape).astype(np.float64)
    nn_ops.conv3d_transpose(
        x_value, f_value, y_shape, strides, data_format='NCDHW')

  def testConv3DTransposeOutputShapeType(self):
...
    self.assertLess(err, err_tolerance)


if __name__ == "__main__":
// --- conv_grad_ops_3d.cc ---
...
                   context->allocate_output(0, input_shape, &in_backprop));

    auto* stream = context->op_device_context()->stream();
