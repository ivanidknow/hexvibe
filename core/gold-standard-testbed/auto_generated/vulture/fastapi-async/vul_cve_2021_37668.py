# Vulnerable: VUL-CVE-2021-37668
for dtype in [dtypes.int32, dtypes.int64]:
        with self.assertRaisesRegex(errors.InvalidArgumentError,
                                    "index is out of bound as with dims"):
          indices = constant_op.constant([2, 5, 7], dtype=dtype)
          dims = constant_op.constant([3, 0], dtype=dtype)
// --- unravel_index_op.cc ---
    auto dims = dims_tensor.vec<Tidx>();

    // Chek to make sure indices is not out of boundary
