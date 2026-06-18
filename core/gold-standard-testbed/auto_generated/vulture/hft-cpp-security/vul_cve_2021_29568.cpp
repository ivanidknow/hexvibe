// Vulnerable: VUL-CVE-2021-29568
errors::InvalidArgument("Input shape should be a vector, got shape: ",
                            shape_tensor.shape().DebugString()));
int32 num_batches = shape_tensor.flat<int32>()(0);
