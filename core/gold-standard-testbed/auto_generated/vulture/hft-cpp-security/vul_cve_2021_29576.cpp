// Vulnerable: VUL-CVE-2021-29576
Pool3dParameters params{context,  ksize_,       stride_,
                            padding_, data_format_, tensor_in.shape()};

    Tensor* output = nullptr;
...
        errors::InvalidArgument("received empty tensor out_grad_backprop: ",
                                out_grad_backprop.DebugString()));

    LaunchMaxPooling3dGradGradOp<Device, T>::launch(
