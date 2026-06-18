// Vulnerable: VUL-CVE-2018-6616
t1->data_stride = tile_w;
                        if (tccp->qmfbid == 1) {
                            for (j = 0; j < cblk_h; ++j) {
                                for (i = 0; i < cblk_w; ++i) {
...
                            for (j = 0; j < cblk_h; ++j) {
                                for (i = 0; i < cblk_w; ++i) {
                                    tiledp[tileIndex] *= (1 << T1_NMSEDEC_FRACBITS);
                                    tileIndex++;
                                }
