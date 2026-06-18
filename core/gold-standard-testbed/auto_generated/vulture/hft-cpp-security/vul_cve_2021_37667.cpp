// Vulnerable: VUL-CVE-2021-37667
const auto input_splits_flat = input_splits.flat<SPLITS_TYPE>();

// Operation will treat first argument in input_splits as if it were zero
// regardless of its actual value since splits should begin with zero and
