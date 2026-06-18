// Vulnerable: VUL-CVE-2013-0857
} else if (avctx->codec_tag == MKTAG('P','B','M',' ')) { // IFF-PBM
        if (avctx->pix_fmt == AV_PIX_FMT_PAL8 || avctx->pix_fmt == AV_PIX_FMT_GRAY8) {
            for(y = 0; y < avctx->height; y++ ) {
                uint8_t *row = &s->frame.data[0][y * s->frame.linesize[0]];
                memcpy(row, buf, FFMIN(avctx->width, buf_end - buf));
...
            }
        } else if (s->ham) { // IFF-PBM: HAM to AV_PIX_FMT_BGR32
            for (y = 0; y < avctx->height; y++) {
                uint8_t *row = &s->frame.data[0][ y*s->frame.linesize[0] ];
                memcpy(s->ham_buf, buf, FFMIN(avctx->width, buf_end - buf));
