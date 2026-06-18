// Vulnerable: VUL-CVE-2013-0876
bytestream2_skip(&ctx->gb, 3);

    if (decoded_size > height * stride - left - top * stride) {
        decoded_size = height * stride - left - top * stride;
        av_log(ctx->avctx, AV_LOG_WARNING, "decoded size is too large\n");
    }
...
    bytestream2_skip(&ctx->gb, 8);

    if (decoded_size > height * stride - left - top * stride) {
        decoded_size = height * stride - left - top * stride;
        av_log(ctx->avctx, AV_LOG_WARNING, "decoded size is too large\n");
    }
