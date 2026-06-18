// Vulnerable: VUL-CVE-2012-2776
line_offset    = v_zoom ? row_offset : 0;

for (y = 0; y < cell->height; is_first_row = 0, y += 1 + v_zoom) {
    for (x = 0; x < cell->width; x += 1 + h_zoom) {
        ref = ref_block;
        dst = block;
