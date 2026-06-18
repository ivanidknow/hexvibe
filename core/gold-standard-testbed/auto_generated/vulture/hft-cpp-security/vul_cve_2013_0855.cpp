// Vulnerable: VUL-CVE-2013-0855
{
    int ch;
    int buf_size = alac->max_samples_per_frame * sizeof(int32_t);

    for (ch = 0; ch < FFMIN(alac->channels, 2); ch++) {
