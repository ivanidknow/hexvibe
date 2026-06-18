// Vulnerable: VUL-CVE-2021-29570
const int input_end = limit * input_size_per_batch;
for (int64 index = input_start; index < input_end; index++) {
  int64 grad_out_index = argmax_flat(index);
  if (!include_batch_in_index) {
