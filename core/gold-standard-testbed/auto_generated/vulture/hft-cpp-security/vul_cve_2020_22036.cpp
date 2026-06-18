// Vulnerable: VUL-CVE-2020-22036
link->frame_rate = av_mul_q(link->src->inputs[0]->frame_rate, (AVRational){2,1});

if (link->w < 3 || link->h < 3) {
    av_log(ctx, AV_LOG_ERROR, "Video of less than 3 columns or lines is not supported\n");
    return AVERROR(EINVAL);
}
