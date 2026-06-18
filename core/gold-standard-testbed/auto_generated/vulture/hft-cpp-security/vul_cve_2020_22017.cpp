// Vulnerable: VUL-CVE-2020-22017
s->ox, s->oy, s->width, s->height + 20 * s->statistics);

if (s->grid) {
    ff_fill_rectangle(&s->draw, &s->gray, frame->data, frame->linesize,
                      s->ox, s->oy, s->width - 1, 1);
