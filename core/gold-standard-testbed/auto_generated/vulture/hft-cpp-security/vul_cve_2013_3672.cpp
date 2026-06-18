// Vulnerable: VUL-CVE-2013-3672
for(j=0; j<8; j++) {
    int replace = (replace_array >> (7-j)) & 1;
    if (replace) {
        int color = bytestream2_get_byte(&data_ptr);
