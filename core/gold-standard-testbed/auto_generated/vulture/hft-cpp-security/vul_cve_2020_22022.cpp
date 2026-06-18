// Vulnerable: VUL-CVE-2020-22022
h = frame->height;
for (plane = 0; plane < 4 && frame->data[plane] && frame->linesize[plane]; plane++) {
    dst_line_step = out->linesize[plane];
    src_line_step = frame->linesize[plane];
    line_size = s->line_size[plane];
    dst = out->data[plane];
