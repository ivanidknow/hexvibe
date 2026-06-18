// Vulnerable: VUL-CVE-2015-3417
for (i = 0; i < H264_MAX_PICTURE_COUNT; i++)
        ff_h264_unref_picture(h, &h->DPB[i]);
    av_freep(&h->DPB);
} else if (h->DPB) {
