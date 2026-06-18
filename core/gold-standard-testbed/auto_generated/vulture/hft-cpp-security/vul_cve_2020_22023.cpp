// Vulnerable: VUL-CVE-2020-22023
if (s->depth <= 8) {
        for (plane = 0; plane < s->nb_planes; plane++) {
            const int linesize = in->linesize[plane];
            const int dlinesize = out->linesize[plane];
            uint8_t *val = in->data[plane];
...
    } else {
        for (plane = 0; plane < s->nb_planes; plane++) {
            const int linesize = in->linesize[plane] / 2;
            const int dlinesize = out->linesize[plane] / 2;
            uint16_t *val = (uint16_t *)in->data[plane];
