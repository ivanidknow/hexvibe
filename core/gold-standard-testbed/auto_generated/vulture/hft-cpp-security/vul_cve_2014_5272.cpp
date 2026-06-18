// Vulnerable: VUL-CVE-2014-5272
case 4:
        bytestream2_init(&gb, buf, buf_size);
        if (avctx->codec_tag == MKTAG('R', 'G', 'B', '8'))
            decode_rgb8(&gb, s->frame->data[0], avctx->width, avctx->height, s->frame->linesize[0]);
        else if (avctx->codec_tag == MKTAG('R', 'G', 'B', 'N'))
...
        if (avctx->codec_tag == MKTAG('R', 'G', 'B', '8'))
            decode_rgb8(&gb, s->frame->data[0], avctx->width, avctx->height, s->frame->linesize[0]);
        else if (avctx->codec_tag == MKTAG('R', 'G', 'B', 'N'))
            decode_rgbn(&gb, s->frame->data[0], avctx->width, avctx->height, s->frame->linesize[0]);
        else
