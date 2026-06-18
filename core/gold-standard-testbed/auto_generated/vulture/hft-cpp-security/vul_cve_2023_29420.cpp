// Vulnerable: VUL-CVE-2023-29420
if (bwt_idx == -1) {
    if (data_size - 8 > 64) {
        state->last_error = BZ3_ERR_MALFORMED_HEADER;
        return -1;
