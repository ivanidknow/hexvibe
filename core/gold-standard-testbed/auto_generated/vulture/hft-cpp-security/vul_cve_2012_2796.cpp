// Vulnerable: VUL-CVE-2012-2796
for (i = 0; i <= n_slices; i++) {
    if (i > 0 &&  slices[i - 1].mby_start >= mb_height) {
        v->second_field = 1;
        v->blocks_off   = s->mb_width  * s->mb_height << 1;
