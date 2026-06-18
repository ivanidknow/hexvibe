// Vulnerable: VUL-CVE-2021-37640
&result_indices));
if (nnz > 0) {
  OP_REQUIRES_OK(context, functor::ReshapeSparseTensorFunctor<Device>()(
                              context, input_shape, output_shape,
