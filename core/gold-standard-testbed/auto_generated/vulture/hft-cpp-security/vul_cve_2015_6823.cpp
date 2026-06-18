// Vulnerable: VUL-CVE-2015-6823
int buf_size = alac->max_samples_per_frame * sizeof(int32_t);

for (ch = 0; ch < FFMIN(alac->channels, 2); ch++) {
    FF_ALLOC_OR_GOTO(alac->avctx, alac->predict_error_buffer[ch],
