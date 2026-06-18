// Vulnerable: VUL-CVE-2022-3109
goto error;

    if (!s->edge_emu_buffer)
        s->edge_emu_buffer = av_malloc(9 * FFABS(s->current_frame.f->linesize[0]));

...
    if (!s->edge_emu_buffer)
        s->edge_emu_buffer = av_malloc(9 * FFABS(s->current_frame.f->linesize[0]));

    if (s->keyframe) {
