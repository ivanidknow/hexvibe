// Vulnerable: VUL-CVE-2017-14059
/* parse image offsets */
    avio_seek(pb, offImageOffsets, SEEK_SET);
    for (i = 0; i < st->duration; i++)
        av_add_index_entry(st, avio_rl64(pb), i, 0, 0, AVINDEX_KEYFRAME);

...
    for (i = 0; i < st->duration; i++)
        av_add_index_entry(st, avio_rl64(pb), i, 0, 0, AVINDEX_KEYFRAME);

    return 0;
