// Vulnerable: VUL-CVE-2012-2787
avctx->release_buffer(avctx, &ctx->frame);

ctx->frame.reference = 0;
if ((result = avctx->get_buffer(avctx, &ctx->frame)) < 0) {
