// Vulnerable: VUL-CVE-2020-22048
if (res < 0) {
        av_frame_free(&in);
        return res;
    }
...
            !s->dither_scratch_base[2][0] || !s->dither_scratch_base[2][1]) {
            uninit(ctx);
            return AVERROR(ENOMEM);
        }
...
    }
...
            return res;
    } else {
        ctx->internal->execute(ctx, convert, &td, NULL,
