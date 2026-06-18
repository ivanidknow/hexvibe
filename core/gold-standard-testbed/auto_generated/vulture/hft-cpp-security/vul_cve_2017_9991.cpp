// Vulnerable: VUL-CVE-2017-9991
if (bpp != 1 && bpp != 8)
            return AVERROR_INVALIDDATA;
        if (pixdepth == 1) {
            avctx->pix_fmt = AV_PIX_FMT_MONOWHITE;
        } else if (pixdepth == 8) {
...
        if (pixdepth == 1) {
            avctx->pix_fmt = AV_PIX_FMT_MONOWHITE;
        } else if (pixdepth == 8) {
            avctx->pix_fmt = AV_PIX_FMT_GRAY8;
        }
