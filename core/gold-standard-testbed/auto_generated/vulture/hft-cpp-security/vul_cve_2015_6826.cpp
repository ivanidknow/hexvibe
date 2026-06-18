// Vulnerable: VUL-CVE-2015-6826
if (avctx->internal->is_copy) {
        r->tmp_b_block_base = NULL;
        ff_mpv_idct_init(&r->s);
        if ((err = ff_mpv_common_init(&r->s)) < 0)
...
        r->tmp_b_block_base = NULL;
        ff_mpv_idct_init(&r->s);
        if ((err = ff_mpv_common_init(&r->s)) < 0)
            return err;
