// Vulnerable: VUL-CVE-2013-0859
double *dp;

    if (count >= INT_MAX / sizeof(int64_t))
        return AVERROR_INVALIDDATA;
    if (bytestream2_get_bytes_left(&s->gb) < count * sizeof(int64_t))
...
    int16_t *sp;

    if (count >= INT_MAX / sizeof(int16_t))
        return AVERROR_INVALIDDATA;
    if (bytestream2_get_bytes_left(&s->gb) < count * sizeof(int16_t))
