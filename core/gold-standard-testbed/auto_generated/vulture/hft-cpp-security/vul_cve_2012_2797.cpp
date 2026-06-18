// Vulnerable: VUL-CVE-2012-2797
/* get output buffer */
s->frame->nb_samples = MPA_FRAME_SIZE;
if ((ret = avctx->get_buffer(avctx, s->frame)) < 0) {
    av_log(avctx, AV_LOG_ERROR, "get_buffer() failed\n");
