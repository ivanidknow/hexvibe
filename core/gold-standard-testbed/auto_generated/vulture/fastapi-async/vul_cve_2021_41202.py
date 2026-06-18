# Vulnerable: VUL-CVE-2021-41202
with self.assertRaises(errors_impl.ResourceExhaustedError):
        v = math_ops.range(0, 9223372036854775807)
        self.evaluate(v)
// --- sequence_ops.cc ---
      size = static_cast<int64>(std::ceil(std::abs((limit - start) / delta)));
    }
    Tensor* out = nullptr;
    OP_REQUIRES_OK(context,
...
    }
    Tensor* out = nullptr;
...
                   context->allocate_output(0, TensorShape({size}), &out));
    auto flat = out->flat<T>();
    T val = start;
