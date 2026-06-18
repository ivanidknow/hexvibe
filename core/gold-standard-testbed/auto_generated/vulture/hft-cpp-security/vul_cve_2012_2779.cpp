// Vulnerable: VUL-CVE-2012-2779
uint32_t        lock_word;
    IVIPicConfig    pic_conf;
} IVI5DecContext;

...

    if (ctx->frame_type == FRAMETYPE_INTRA) {
        if (decode_gop_header(ctx, avctx))
            return -1;
...
        if (decode_gop_header(ctx, avctx))
...
    if (result) {
        av_log(avctx, AV_LOG_ERROR,
               "Error while decoding picture header: %d\n", result);
