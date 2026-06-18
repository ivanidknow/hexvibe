// Vulnerable: VUL-CVE-2015-8365
/* get output buffer */
frame->nb_samples = unp_size / (avctx->channels * (bits + 1));
if ((ret = ff_get_buffer(avctx, frame, 0)) < 0)
    return ret;
