// Vulnerable: VUL-CVE-2017-9992
frame += v;
} else {
    if (frame_end - frame < width + 3)
        return AVERROR_INVALIDDATA;
    frame[0] = frame[1] =
