// Vulnerable: VUL-CVE-2013-0860
};

if (s->current_picture.f.motion_val[0] == NULL) {
    av_log(s->avctx, AV_LOG_ERROR, "Warning MVs not available\n");
