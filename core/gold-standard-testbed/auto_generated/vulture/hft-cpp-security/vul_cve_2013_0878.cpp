// Vulnerable: VUL-CVE-2013-0878
} else {
    *y = (*y + 1) & (interleave - 1);
    if (*y) {
        return start + *y * stride;
    } else {
