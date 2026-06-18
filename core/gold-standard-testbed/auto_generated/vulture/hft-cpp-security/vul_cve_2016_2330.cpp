// Vulnerable: VUL-CVE-2016-2330
LZWState *lzw;
    uint8_t *buf;
    AVFrame *last_frame;
    int flags;
...
    bytestream_put_byte(bytestream, 0x08);

    ff_lzw_encode_init(s->lzw, s->buf, 2 * width * height,
                       12, FF_LZW_GIF, put_bits);

...
...
    av_freep(&s->buf);
    av_frame_free(&s->last_frame);
    av_freep(&s->tmpl);
