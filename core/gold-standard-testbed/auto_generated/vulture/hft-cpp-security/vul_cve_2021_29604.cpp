// Vulnerable: VUL-CVE-2021-29604
const int num_rows = SizeOfDimension(value, 0);
const int row_bytes = value->bytes / num_rows;
void* pointer = nullptr;
