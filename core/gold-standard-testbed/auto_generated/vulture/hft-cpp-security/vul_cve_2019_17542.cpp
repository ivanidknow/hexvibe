// Vulnerable: VUL-CVE-2019-17542
s->width = AV_RL16(&s->avctx->extradata[6]);
s->height = AV_RL16(&s->avctx->extradata[8]);
if ((ret = av_image_check_size(s->width, s->height, 0, avctx)) < 0) {
    s->width= s->height= 0;
    return ret;
