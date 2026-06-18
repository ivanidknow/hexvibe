// Vulnerable: VUL-CVE-2022-23588
input_tensor.ToString(),
                      " has a dtype of DT_INVALID."));
}
Tensor* value = new Tensor(raw_val.dtype(), raw_val.tensor_shape());
