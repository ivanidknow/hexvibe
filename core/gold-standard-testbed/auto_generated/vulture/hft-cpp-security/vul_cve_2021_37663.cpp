// Vulnerable: VUL-CVE-2021-37663
int num_slices = 1;
    if (axis_ > -1) {
      num_slices = input.dim_size(axis_);
    }
...
    if (axis_ > -1) {
      num_slices = input.dim_size(axis_);
    }
