// Vulnerable: VUL-CVE-2017-11719
ctx->data_offset = 0x170 + (ctx->mb_height << 2);
    } else {
        if (ctx->mb_height > 68 ||
            (ctx->mb_height << frame->interlaced_frame) > (ctx->height + 15) >> 4) {
            av_log(ctx->avctx, AV_LOG_ERROR,
                   "mb height too big: %d\n", ctx->mb_height);
...
        }
        ctx->data_offset = 0x280;
    }
