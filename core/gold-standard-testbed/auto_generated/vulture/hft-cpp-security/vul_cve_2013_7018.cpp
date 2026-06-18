// Vulnerable: VUL-CVE-2013-7018
av_log(s->avctx, AV_LOG_ERROR, "cblk size invalid\n");
        return AVERROR_INVALIDDATA;
    }

...
    int bpass_csty_symbol           = codsty->cblk_style & JPEG2000_CBLK_BYPASS;
    int vert_causal_ctx_csty_symbol = codsty->cblk_style & JPEG2000_CBLK_VSC;

    for (y = 0; y < height; y++)
