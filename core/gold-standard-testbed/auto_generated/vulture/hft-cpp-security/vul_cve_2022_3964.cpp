// Vulnerable: VUL-CVE-2022-3964
// loop thru and compare pixels
    for (y = 0; y < bi->block_height; y++) {
        for (x = 0; x < bi->block_width; x++){
            // TODO:  optimize
            min_r = FFMIN(R(block_ptr[x]), min_r);
...

    for (i = 0; i < bi->block_height; i++) {
        for (j = 0; j < bi->block_width; j++){
            x = GET_CHAN(block_ptr[j], xchannel);
            y = GET_CHAN(block_ptr[j], ychannel);
...
                    }
                    row_ptr += bi.rowstride;
                }
