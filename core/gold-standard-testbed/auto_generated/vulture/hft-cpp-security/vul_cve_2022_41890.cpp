// Vulnerable: VUL-CVE-2022-41890
// Safely multiplies dimensions taking into account symbolic shapes.
  auto mul_dims = [](int64_t dim1, int64_t dim2) -> int64 {
    return dim1 != 0 && dim2 != 0 && (dim1 < 0 || dim2 < 0) ? -1 : dim1 * dim2;
  };
...
  Vec output;
  bool output_dim_set = false;
  int output_dim = -1;
  bool none_is_one = true;
  bool set_one = false;
// --- bcast_test.cc ---
            "[11,7,5,3,2]"
            "[0,1,2,3,4][]");
}
