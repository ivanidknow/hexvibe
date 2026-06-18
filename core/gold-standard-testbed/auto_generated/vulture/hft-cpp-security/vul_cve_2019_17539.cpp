// Vulnerable: VUL-CVE-2019-17539
return ret;
free_and_end:
    if (avctx->codec &&
        (codec_init_ok ||
         (avctx->codec->caps_internal & FF_CODEC_CAP_INIT_CLEANUP)))
