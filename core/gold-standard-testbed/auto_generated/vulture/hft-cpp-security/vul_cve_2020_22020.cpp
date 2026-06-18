// Vulnerable: VUL-CVE-2020-22020
fm->tpitchuv = FFALIGN(w >> 1, 16);

fm->tbuffer = av_malloc(h/2 * fm->tpitchy);
fm->c_array = av_malloc((((w + fm->blockx/2)/fm->blockx)+1) *
                        (((h + fm->blocky/2)/fm->blocky)+1) *
