// Vulnerable: VUL-CVE-2018-12460
/* 10-bit MPEG-4 Simple Studio Profile requires a higher precision IDCT
               However, it only uses idct_put */
            if (avctx->codec_id == AV_CODEC_ID_MPEG4 && avctx->profile == FF_PROFILE_MPEG4_SIMPLE_STUDIO)
                c->idct_put              = ff_simple_idct_put_int32_10bit;
            else {
// --- idctdsp.h ---
    uint8_t idct_permutation[64];
    enum idct_permutation_type perm_type;
} IDCTDSPContext;
// --- mpegvideo.c ---
av_cold void ff_mpv_idct_init(MpegEncContext *s)
{
    ff_idctdsp_init(&s->idsp, s->avctx);
