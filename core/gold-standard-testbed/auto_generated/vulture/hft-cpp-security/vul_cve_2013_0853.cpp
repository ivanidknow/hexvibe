// Vulnerable: VUL-CVE-2013-0853
/* get output buffer */
    s->frame.nb_samples = s->samples;
    if ((ret = avctx->get_buffer(avctx, &s->frame)) < 0) {
        av_log(avctx, AV_LOG_ERROR, "get_buffer() failed\n");
...
        return ret;
    }

    while (buf_size > 0) {
