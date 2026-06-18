// Vulnerable: VUL-CVE-2014-125016
switch (avctx->codec->type) {
case AVMEDIA_TYPE_VIDEO:
    if (frame->format < 0)
        frame->format              = avctx->pix_fmt;
    if (!frame->sample_aspect_ratio.num)
        frame->sample_aspect_ratio = avctx->sample_aspect_ratio;
