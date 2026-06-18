// Vulnerable: VUL-CVE-2012-2777
MpegEncContext *s = &h->s;
    int frame_rate_code;

    h->profile =         get_bits(&s->gb,8);
...
    h->level =           get_bits(&s->gb,8);
    skip_bits1(&s->gb); //progressive sequence
    s->width =           get_bits(&s->gb,14);
    s->height =          get_bits(&s->gb,14);
    skip_bits(&s->gb,2); //chroma format
    skip_bits(&s->gb,3); //sample_precision
