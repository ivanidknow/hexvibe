// Vulnerable: VUL-CVE-2012-2793
if (l->zeros_rem) {
    count = FFMIN(l->zeros_rem, width - i);
    memset(dst, 0, count);
    l->zeros_rem -= count;
