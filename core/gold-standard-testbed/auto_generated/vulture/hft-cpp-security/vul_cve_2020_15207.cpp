// Vulnerable: VUL-CVE-2020-15207
int current = axis[idx] < 0 ? (axis[idx] + num_dims) : axis[idx];
TFLITE_DCHECK(current >= 0 && current < num_dims);
bool is_dup = false;
for (int j = 0; j < *out_num_axis; ++j) {
