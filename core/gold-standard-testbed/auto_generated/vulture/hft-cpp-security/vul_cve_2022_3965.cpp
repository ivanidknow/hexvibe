// Vulnerable: VUL-CVE-2022-3965
row_ptr += stride * 4; \
            pixel_ptr = row_ptr; \
        } \
    } \
...
    uint8_t *distinct_values = s->distinct_values;
    const uint8_t *pixel_ptr, *row_ptr;
    const int width = frame->width;
    uint8_t block_values[16];
...
    int color_table_index;  /* indexes to color pair, quad, or octet tables */
...
        row_ptr = xrow_ptr;

        blocks = coded_blocks;
