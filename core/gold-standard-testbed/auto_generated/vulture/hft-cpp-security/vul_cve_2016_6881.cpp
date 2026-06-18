// Vulnerable: VUL-CVE-2016-6881
ret = inflate(z, Z_NO_FLUSH);
    if (ret < 0)
        return AVERROR(EINVAL);
    if (ret == Z_STREAM_END)
        return AVERROR_EOF;
...
    if (ret == Z_STREAM_END)
        return AVERROR_EOF;

    if (buf_size - z->avail_out == 0)
