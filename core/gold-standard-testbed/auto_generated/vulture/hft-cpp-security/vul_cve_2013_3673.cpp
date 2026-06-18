// Vulnerable: VUL-CVE-2013-3673
if (s->keyframe) {
    s->keyframe_ok = 0;
    if ((ret = gif_read_header1(s)) < 0)
        return ret;
