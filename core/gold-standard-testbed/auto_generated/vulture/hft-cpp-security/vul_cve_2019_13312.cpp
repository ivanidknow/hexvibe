// Vulnerable: VUL-CVE-2019-13312
c->pstride = FFALIGN((avctx->width + c->lrange) * c->bypp, 16);
prev_size = FFALIGN(c->lrange * c->bypp, 16) + c->pstride * (c->lrange + avctx->height + c->urange);
prev_offset = FFALIGN(c->lrange, 16) + c->pstride * c->lrange;
if (!(c->prev_buf = av_mallocz(prev_size))) {
    av_log(avctx, AV_LOG_ERROR, "Can't allocate picture.\n");
