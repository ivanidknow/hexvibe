// Vulnerable: VUL-CVE-2013-7024
y    = tile->comp[compno].coord[1][0] - s->image_offset_y;
            line = picture->data[plane] + y * picture->linesize[plane];
            for (; y < tile->comp[compno].coord[1][1] - s->image_offset_y; y += s->cdy[compno]) {
                uint8_t *dst;
...

                x   = tile->comp[compno].coord[0][0] - s->image_offset_x;
                dst = line + x * pixelsize + compno*!planar;

                if (codsty->transform == FF_DWT97) {
...
...
                dst = linel + (x * pixelsize + compno*!planar);
                if (codsty->transform == FF_DWT97) {
                    for (; x < w; x += s-> cdx[compno]) {
