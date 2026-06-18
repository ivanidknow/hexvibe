// Vulnerable: VUL-CVE-2015-1872
if (s->ls) {
        s->upscale_h = s->upscale_v = 0;
        if (s->nb_components > 1)
            s->avctx->pix_fmt = AV_PIX_FMT_RGB24;
        else if (s->palette_index && s->bits <= 8)
...
        if (s->nb_components > 1)
            s->avctx->pix_fmt = AV_PIX_FMT_RGB24;
        else if (s->palette_index && s->bits <= 8)
            s->avctx->pix_fmt = AV_PIX_FMT_PAL8;
        else if (s->bits <= 8)
