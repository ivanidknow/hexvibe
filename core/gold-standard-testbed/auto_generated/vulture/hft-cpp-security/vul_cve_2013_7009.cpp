// Vulnerable: VUL-CVE-2013-7009
int row_ptr = 0;
    int pixel_ptr = 0;
    int block_ptr;
    int pixel_x, pixel_y;
...
            stream_ptr += 2;
            while (n_blocks--) {
                block_ptr = row_ptr + pixel_ptr;
                for (pixel_y = 0; pixel_y < 4; pixel_y++) {
...
                    block_ptr += row_inc;
...
            }
            ADVANCE_BLOCK();
            break;
