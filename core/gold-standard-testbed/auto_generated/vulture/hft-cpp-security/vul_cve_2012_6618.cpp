// Vulnerable: VUL-CVE-2012-6618
AVProbeData pd = { filename ? filename : "", NULL, -offset };
    unsigned char *buf = NULL;
    int ret = 0, probe_size;

    if (!max_probe_size) {
...
        probe_size = FFMIN(probe_size<<1, FFMAX(max_probe_size, probe_size+1))) {
        int score = probe_size < max_probe_size ? AVPROBE_SCORE_RETRY : 0;
        int buf_offset = (probe_size == PROBE_BUF_MIN) ? 0 : probe_size>>1;
        void *buftmp;

...
        }
        pd.buf_size += ret;
        pd.buf = &buf[offset];
