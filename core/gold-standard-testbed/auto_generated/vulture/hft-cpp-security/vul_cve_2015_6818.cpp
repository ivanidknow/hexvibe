// Vulnerable: VUL-CVE-2015-6818
if (s->state & PNG_IDAT) {
    av_log(avctx, AV_LOG_ERROR, "IHDR after IDAT\n");
    return AVERROR_INVALIDDATA;
}
