// Vulnerable: VUL-CVE-2021-29574
{2}, 0, tensor_out.shape(), &output));

LaunchMaxPooling3dGradGradOp<Device, T>::launch(
    context, params, tensor_in, tensor_out, out_grad_backprop, output);
