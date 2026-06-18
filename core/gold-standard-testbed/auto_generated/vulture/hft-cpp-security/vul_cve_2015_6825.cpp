// Vulnerable: VUL-CVE-2015-6825
copy->internal = av_malloc(sizeof(AVCodecInternal));
if (!copy->internal) {
    err = AVERROR(ENOMEM);
    goto error;
