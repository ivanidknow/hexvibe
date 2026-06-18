// Vulnerable: VUL-CVE-2014-125002
static av_cold int dnxhd_init_rc(DNXHDEncContext *ctx)
{
    FF_ALLOCZ_OR_GOTO(ctx->m.avctx, ctx->mb_rc, 8160*ctx->m.avctx->qmax*sizeof(RCEntry), fail);
    if (ctx->m.avctx->mb_decision != FF_MB_DECISION_RD)
        FF_ALLOCZ_OR_GOTO(ctx->m.avctx, ctx->mb_cmp, ctx->m.mb_num*sizeof(RCCMPEntry), fail);
