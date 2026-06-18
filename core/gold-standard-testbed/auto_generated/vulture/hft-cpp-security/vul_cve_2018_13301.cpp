// Vulnerable: VUL-CVE-2018-13301
}

static int mpeg4_decode_profile_level(MpegEncContext *s, GetBitContext *gb)
{

    s->avctx->profile = get_bits(gb, 4);
    s->avctx->level   = get_bits(gb, 4);

    // for Simple profile, level 0
...

...
    if (s->studio_profile) {
        if (!s->avctx->bits_per_raw_sample) {
            av_log(s->avctx, AV_LOG_ERROR, "Missing VOL header\n");
