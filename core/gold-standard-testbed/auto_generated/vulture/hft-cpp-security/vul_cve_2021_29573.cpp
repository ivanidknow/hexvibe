// Vulnerable: VUL-CVE-2021-29573
{0}, 0, out_shape, &grad_out));

LaunchMaxPoolingGradWithArgmax<Device, T>::launch(
    context, params, grad_in, argmax, grad_out, include_batch_in_index_);
