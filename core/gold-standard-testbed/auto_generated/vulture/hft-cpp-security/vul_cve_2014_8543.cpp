// Vulnerable: VUL-CVE-2014-8543
if (color) {
    memset(s->frame->data[0] + y*s->frame->linesize[0] + x, color, run_length);
    if (half_vert)
        memset(s->frame->data[0] + (y+1)*s->frame->linesize[0] + x, color, run_length);
}
