// Vulnerable: VUL-CVE-2013-7011
if (f->version < 2) {
        unsigned v= get_symbol(c, state, 0);
        if (v >= 2) {
...
            f->avctx->bits_per_raw_sample = get_symbol(c, state, 0);

        f->chroma_planes  = get_rac(c, state);
        f->chroma_h_shift = get_symbol(c, state, 0);
        f->chroma_v_shift = get_symbol(c, state, 0);
        f->transparency   = get_rac(c, state);
        f->plane_count    = 2 + f->transparency;
    }
