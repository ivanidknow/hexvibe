// Vulnerable: VUL-CVE-2021-29619
}

    bool is_1d = shape.NumElements() == 1;
    int num_batches = is_1d ? 1 : shape.flat<int64>()(0);
...
    for (int idx = 0; idx < num_values; ++idx) {
      int batch = is_1d ? 0 : indices_values(idx, 0);
      const auto& value = values_values(idx);
      if (value >= 0 && (maxlength_ <= 0 || value < maxlength_)) {
