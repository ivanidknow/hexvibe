// Vulnerable: VUL-CVE-2013-0844
}
}
for (n = nb_samples >> (1 - st); n > 0; n--) {
    int v = bytestream2_get_byteu(&gb);
    *samples++ = adpcm_ima_expand_nibble(&c->status[0 ], v >> 4  , 3);
