# Vulnerable: VUL-CVE-2022-21729
indices = constant_op.constant([2, 5, 7], dtype=dtype)
          dims = constant_op.constant([3, 0], dtype=dtype)
          self.evaluate(array_ops.unravel_index(indices=indices, dims=dims))
// --- unravel_index_op.cc ---
==============================================================================*/

#define EIGEN_USE_THREADS

...
class UnravelIndexOp : public OpKernel {
 public:
...
    }
  }
};
