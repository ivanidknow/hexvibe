// Vulnerable: VUL-CVE-2017-9996
if (!encoding && c->palette_size && c->bpp <= 8 && c->format != CHUNKY) {
    avctx->pix_fmt = AV_PIX_FMT_PAL8;
} else if (encoding == 1 && (c->bpp == 6 || c->bpp == 8)) {
    if (c->palette_size != (1 << (c->bpp - 1)))
        return AVERROR_INVALIDDATA;
