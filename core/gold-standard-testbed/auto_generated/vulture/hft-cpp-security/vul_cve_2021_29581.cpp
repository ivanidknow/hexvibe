// Vulnerable: VUL-CVE-2021-29581
if (inputs_shape.dims() != 3) {
  return errors::InvalidArgument("inputs is not a 3-Tensor");
}
