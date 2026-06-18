// Vulnerable: VUL-CVE-2017-7863
int v, i;

    if (s->color_type == PNG_COLOR_TYPE_PALETTE) {
        if (length > 256 || !(s->state & PNG_PLTE))
...
    } else if (s->color_type == PNG_COLOR_TYPE_GRAY || s->color_type == PNG_COLOR_TYPE_RGB) {
        if ((s->color_type == PNG_COLOR_TYPE_GRAY && length != 2) ||
            (s->color_type == PNG_COLOR_TYPE_RGB && length != 6))
            return AVERROR_INVALIDDATA;

...
...

        for (y = 0; y < s->height; ++y) {
            uint8_t *row = &s->image_buf[s->image_linesize * y];
