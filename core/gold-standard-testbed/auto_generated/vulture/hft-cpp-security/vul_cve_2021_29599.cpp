// Vulnerable: VUL-CVE-2021-29599
const int input_size = SizeOfDimension(input, axis_value);
TF_LITE_ENSURE_MSG(context, input_size % num_splits == 0,
                   "Not an even split");
