// Vulnerable: VUL-CVE-2013-7016
s->cdx[i]    = bytestream2_get_byteu(&s->g);
s->cdy[i]    = bytestream2_get_byteu(&s->g);
if (!s->cdx[i] || !s->cdy[i]) {
    av_log(s->avctx, AV_LOG_ERROR, "Invalid sample seperation\n");
    return AVERROR_INVALIDDATA;
