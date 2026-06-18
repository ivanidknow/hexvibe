// Vulnerable: VUL-CVE-2012-2801
avctx->pix_fmt = PIX_FMT_PAL8;
    avcodec_get_frame_defaults(&avs->picture);
    return 0;
}
