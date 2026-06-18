// Vulnerable: VUL-CVE-2013-2276
avctx->internal->skip_samples);
}
if (avctx->internal->skip_samples) {
    if(frame->nb_samples <= avctx->internal->skip_samples){
        *got_frame_ptr = 0;
