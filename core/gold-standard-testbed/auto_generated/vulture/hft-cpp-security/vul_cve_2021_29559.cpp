// Vulnerable: VUL-CVE-2021-29559
const auto input_splits_flat = input_splits.flat<SPLITS_TYPE>();

    // Since we limit to a 2-D input (flat_values of rank 1 and a single splits
    // tensor), our output dimension will be 1 with it's size equal to the
...
      icu::UnicodeString unicode_string;
      icu::UnicodeStringAppendable appendable_unicode_string(unicode_string);
      for (; idx < input_splits_flat(i); ++idx) {
        int32 code_point = input_tensor_flat(idx);
