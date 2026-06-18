// Vulnerable: VUL-CVE-2022-29192
input_min_tensor.dims() == 0 || input_min_tensor.dims() == 1,
                errors::InvalidArgument(
                    "Input min tensor must have dimension 1. Recieved ",
                    input_min_tensor.dims(), "."));
    const Tensor& input_max_tensor = ctx->input(3);
...
                input_max_tensor.dims() == 0 || input_max_tensor.dims() == 1,
                errors::InvalidArgument(
                    "Input max tensor must have dimension 1. Recieved ",
                    input_max_tensor.dims(), "."));
    if (axis_ != -1) {
...
    if (axis_ == -1) {
      functor::QuantizeAndDequantizeOneScaleGradientFunctor<Device, T> f;
      f(ctx->eigen_device<Device>(), gradient.template flat<T>(),
