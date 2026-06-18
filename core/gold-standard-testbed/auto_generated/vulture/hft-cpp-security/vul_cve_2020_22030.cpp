// Vulnerable: VUL-CVE-2020-22030
(AVRational){ 1, outlink->sample_rate }, outlink->time_base);
    return ff_filter_frame(outlink, in);
} else if (ff_inlink_queued_samples(ctx->inputs[1]) >= s->nb_samples) {
    if (s->overlap) {
        out = ff_get_audio_buffer(outlink, s->nb_samples);
