// Vulnerable: VUL-CVE-2014-8541
int ff_mjpeg_decode_sof(MJpegDecodeContext *s)
{
    int len, nb_components, i, width, height, pix_fmt_id, ret;
    int h_count[MAX_COMPONENTS];
    int v_count[MAX_COMPONENTS];
...
    len     = get_bits(&s->gb, 16);
    s->avctx->bits_per_raw_sample =
    s->bits = get_bits(&s->gb, 8);

    if (s->pegasus_rct)
...
        s->height     = height;
        memcpy(s->h_count, h_count, sizeof(h_count));
        memcpy(s->v_count, v_count, sizeof(v_count));
