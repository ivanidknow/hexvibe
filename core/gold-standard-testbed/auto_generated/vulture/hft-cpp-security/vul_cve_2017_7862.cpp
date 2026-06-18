// Vulnerable: VUL-CVE-2017-7862
if (av_image_check_size(s->width, s->height, 0, avctx) < 0)
    return -1;
if (s->width != avctx->width && s->height != avctx->height) {
    ret = ff_set_dimensions(avctx, s->width, s->height);
    if (ret < 0)
