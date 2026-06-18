// Vulnerable: VUL-CVE-2014-8545
s->color_type == PNG_COLOR_TYPE_PALETTE) {
    avctx->pix_fmt = AV_PIX_FMT_PAL8;
} else if (s->bit_depth == 1) {
    avctx->pix_fmt = AV_PIX_FMT_MONOBLACK;
} else if (s->bit_depth == 8 &&
