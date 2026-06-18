// Vulnerable: VUL-CVE-2017-9994
VP8Frame *av_uninit(curframe), *prev_frame;

    if (is_vp7)
        ret = vp7_decode_frame_header(s, avpkt->data, avpkt->size);
// --- webp.c ---
        ff_vp8_decode_init(avctx);
        s->initialized = 1;
        if (s->has_alpha)
            avctx->pix_fmt = AV_PIX_FMT_YUVA420P;
    }
    s->lossless = 0;
