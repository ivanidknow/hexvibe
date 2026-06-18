# Vulnerable: VUL-CVE-2022-29206
self.assertLess(err, 1e-3)

  @test_util.run_deprecated_v1
  def testInvalidSparseTensor(self):
    with test_util.force_cpu():
...
      ]:
        sparse = sparse_tensor.SparseTensorValue(bad_idx, val, shape)
        s = sparse_ops.sparse_add(sparse, dense)

        with self.assertRaisesRegex(errors_impl.InvalidArgumentError,
...
  }
  return Status::OK();
}
