// Vulnerable: VUL-CVE-2020-20891
add widthq, remainq
        cmp xq, widthq
        je .end_scalar

        .loop_scalar:
...

        cmp xq, 0
        je .end_scalar_back

        .loop_scalar_back:
...
    s->buffer = av_malloc_array(inlink->w, inlink->h * sizeof(*s->buffer));
    if (!s->buffer)
        return AVERROR(ENOMEM);
