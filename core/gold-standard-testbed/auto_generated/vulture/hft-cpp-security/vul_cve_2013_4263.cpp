// Vulnerable: VUL-CVE-2013-4263
av_frame_copy_props(out, in);

    for (plane = 0; in->data[plane] && plane < 4; plane++)
        hblur(out->data[plane], out->linesize[plane],
              in ->data[plane], in ->linesize[plane],
...
              s->temp);

    for (plane = 0; in->data[plane] && plane < 4; plane++)
        vblur(out->data[plane], out->linesize[plane],
              out->data[plane], out->linesize[plane],
...
    for (plane = 0; plane < 4 && frame->data[plane]; plane++) {
        line_step = frame->linesize[plane];
        line_size = s->line_size[plane];
