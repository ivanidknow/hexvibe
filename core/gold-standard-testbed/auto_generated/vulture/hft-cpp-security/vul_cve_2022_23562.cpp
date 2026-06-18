// Vulnerable: VUL-CVE-2022-23562
# Test case for GitHub issue 46899.
    with self.session():
      with self.assertRaises(errors_impl.InvalidArgumentError):
        v = math_ops.range(start=-1e+38, limit=1)
        self.evaluate(v)
// --- math_ops.cc ---
                   : (Eigen::numext::ceil(
                         Eigen::numext::abs((limit - start) / delta))));
  c->set_output(0, c->Vector(static_cast<int64_t>(size)));
  return Status::OK();
// --- sequence_ops.cc ---
...
    }
    TensorShape shape;
    OP_REQUIRES_OK(context, shape.AddDimWithStatus(size));
