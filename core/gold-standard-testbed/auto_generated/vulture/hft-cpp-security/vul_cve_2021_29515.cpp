// Vulnerable: VUL-CVE-2021-29515
}
  }
  num_rows = context->input(2).flat<int32>()(0);
  num_cols = context->input(3).flat<int32>()(0);
  padding_value = context->input(4).flat<T>()(0);
}
