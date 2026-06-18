// Vulnerable: VUL-CVE-2021-37636
ctx, ctx->allocate_temp(DataTypeToEnum<T>::value, TensorShape({nnz}),
                                &dense_gathered));

    // Pulls relevant entries from the dense side, with reshape and broadcasting
    // *of the dense side* taken into account.  Use a TensorRef to avoid blowing
...
                                  "dense side with broadcasted shape"));       \
      dense_gathered_flat(i) = rhs_ref.coeff(idx);                             \
    }                                                                          \
    break;                                                                     \
