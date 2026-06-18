// Vulnerable: VUL-CVE-2013-3675
h     = bytestream2_get_le16u(&ctx->gb);

if (ctx->width < left + w || ctx->height < top + h) {
    if (av_image_check_size(FFMAX(left + w, ctx->width),
