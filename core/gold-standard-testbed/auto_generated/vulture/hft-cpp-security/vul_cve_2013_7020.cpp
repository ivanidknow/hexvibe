// Vulnerable: VUL-CVE-2013-7020
if (f->version < 2) {
        int chroma_planes, chroma_h_shift, chroma_v_shift, transparency;
        unsigned v= get_symbol(c, state, 0);
        if (v >= 2) {
...
        }

        f->colorspace = get_symbol(c, state, 0); //YUV cs type

        if (f->version > 0)
            f->avctx->bits_per_raw_sample = get_symbol(c, state, 0);
...

        f->chroma_planes  = chroma_planes;
        f->chroma_h_shift = chroma_h_shift;
