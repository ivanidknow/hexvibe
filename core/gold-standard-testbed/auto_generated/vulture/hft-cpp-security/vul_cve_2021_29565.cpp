// Vulnerable: VUL-CVE-2021-29565
done);
// TODO(ebrevdo): add shape checks between values, indices,
// dense_shape.  Also add check that dense rank > 0.

using FunctorType = functor::SparseFillEmptyRows<Device, T, Tindex>;
