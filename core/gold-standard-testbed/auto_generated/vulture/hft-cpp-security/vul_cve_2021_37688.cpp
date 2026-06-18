// Vulnerable: VUL-CVE-2021-37688
input2_data_reset = input2_data_ptr;
  }
} else {
  // Special case of y4 == 1, in which the innermost loop is a single
  // element and can be combined with the next (y3) as an inner broadcast.
