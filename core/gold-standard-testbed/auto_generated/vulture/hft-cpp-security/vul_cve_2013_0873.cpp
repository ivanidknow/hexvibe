// Vulnerable: VUL-CVE-2013-0873
if (s->channels <= 0 || s->channels > MAX_CHANNELS) {
    av_log(s->avctx, AV_LOG_ERROR, "too many channels: %d\n", s->channels);
    return AVERROR_INVALIDDATA;
}
