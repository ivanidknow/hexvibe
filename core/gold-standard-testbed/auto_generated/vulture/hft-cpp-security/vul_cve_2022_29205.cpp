// Vulnerable: VUL-CVE-2022-29205
tensorflow::Safe_PyObjectPtr inner_py_value(
            PySequence_ITEM(py_value, i));
        if (inner_py_value.get() == Py_None) {
          dims[i] = -1;
...
        if (inner_py_value.get() == Py_None) {
          dims[i] = -1;
        } else if (!ParseDimensionValue(key, inner_py_value.get(), status,
                                        &dims[i])) {
          return false;
// --- strided_slice_op.cc ---
...


#undef INSTANTIATE
