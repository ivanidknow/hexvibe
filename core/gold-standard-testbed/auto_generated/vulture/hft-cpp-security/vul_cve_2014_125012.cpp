// Vulnerable: VUL-CVE-2014-125012
int ret;

    if (src_size < avctx->width * avctx->height * bpp) {
        av_log(avctx, AV_LOG_ERROR, "packet too small\n");
        return AVERROR_INVALIDDATA;
...
    int ret;

    if (src_size < avctx->width * avctx->height * 18 / 16) {
        av_log(avctx, AV_LOG_ERROR, "packet too small\n");
        return AVERROR_INVALIDDATA;
...
    if (src_size < avctx->width * avctx->height * 3) {
        av_log(avctx, AV_LOG_ERROR, "packet too small\n");
        return AVERROR_INVALIDDATA;
