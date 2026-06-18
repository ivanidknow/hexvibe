// Vulnerable: VUL-CVE-2021-29579
// in_end)
    FastBoundsCheck(input_backprop_index - in_start, in_end - in_start);
    input_backprop_flat(input_backprop_index) += out_backprop_flat(index);
  }
}
