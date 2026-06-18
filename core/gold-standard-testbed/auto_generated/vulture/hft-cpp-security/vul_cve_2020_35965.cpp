// Vulnerable: VUL-CVE-2020-35965
for (i = 0; i < planes; i++) {
    ptr = picture->data[i];
    for (y = 0; y < s->ymin; y++) {
        memset(ptr, 0, out_line_size);
        ptr += picture->linesize[i];
