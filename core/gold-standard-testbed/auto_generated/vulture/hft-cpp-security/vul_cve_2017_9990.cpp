// Vulnerable: VUL-CVE-2017-9990
uint32_t  *pixels;
    int        pixels_size;
} XPMDecContext;

...
    char color_name[100];

    if (*p == '#') {
        p++;
...
    XPMDecContext *x = avctx->priv_data;
...
    av_freep(&x->pixels);

    return 0;
