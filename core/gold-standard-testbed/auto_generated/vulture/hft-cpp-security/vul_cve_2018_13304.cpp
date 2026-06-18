// Vulnerable: VUL-CVE-2018-13304
if(s->avctx->hwaccel && s->avctx->hwaccel->decode_slice           ||
       !s->cur_pic.f                                                  ||
       s->cur_pic.field_picture                                       ||
       s->avctx->profile == FF_PROFILE_MPEG4_SIMPLE_STUDIO
    )
        return 0;
// --- h263dec.c ---
static enum AVPixelFormat h263_get_format(AVCodecContext *avctx)
{
    /* MPEG-4 Studio Profile only, not supported by hardware */
    if (avctx->bits_per_raw_sample > 8) {
...
        av_assert0(s->avctx->profile == FF_PROFILE_MPEG4_SIMPLE_STUDIO);
        if (!s->avctx->bits_per_raw_sample) {
            av_log(s->avctx, AV_LOG_ERROR, "Missing VOL header\n");
