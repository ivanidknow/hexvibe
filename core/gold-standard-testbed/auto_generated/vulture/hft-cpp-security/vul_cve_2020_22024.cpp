// Vulnerable: VUL-CVE-2020-22024
for (int y = slice_start; y < slice_end; y++) {
    for (int x = 0; x < s->linesize[p]; x++)
        dst[x] = FFMAX(src[x], osrc[x] * decay);
