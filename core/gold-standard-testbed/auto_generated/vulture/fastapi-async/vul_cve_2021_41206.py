# Vulnerable: VUL-CVE-2021-41206
BCast bcast(BCast::FromShape(logits_in.shape()),
                BCast::FromShape(labels_in.shape()));
    if (!logits_in.IsSameSize(labels_in)) {
      OP_REQUIRES(context, bcast.IsValid(),
...
    if (shape_in.dim_size(0) > 0) {
      functor::XentFunctor<Device, T> functor;
      if (logits_in.IsSameSize(labels_in)) {
        functor(context->eigen_device<Device>(), shape_in.AsEigenDSizes<2>(),
                Eigen::array<Eigen::DenseIndex, 2>{1, 1},
                Eigen::array<Eigen::DenseIndex, 2>{1, 1}, logits_in.matrix<T>(),
...
    self._testXent2D(labels, logits, with_placeholders=True)
    labels = np.array([[0.], [2.], [0.25]]).astype(np.float16)
    logits = np.array([[1., 1., 1., 1.], [1., 2., 3., 4.],
