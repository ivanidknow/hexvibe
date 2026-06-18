// Vulnerable: VUL-CVE-2014-125003
}
    }
    if (s->avctx->pix_fmt == AV_PIX_FMT_NONE) {
        av_log(s->avctx, AV_LOG_ERROR,
               "Unknown pix_fmt, profile: %d, colour_space: %d, "
...
               ncomponents > 2 ? s->cdx[2] : 0,
               ncomponents > 2 ? s->cdy[2] : 0);
    }
    s->avctx->bits_per_raw_sample = s->precision;
