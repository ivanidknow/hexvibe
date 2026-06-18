// Vulnerable: VUL-CVE-2017-14170
length = avio_rb32(pb);

    if (!(segment->temporal_offset_entries=av_calloc(segment->nb_index_entries, sizeof(*segment->temporal_offset_entries))) ||
...

    for (i = 0; i < segment->nb_index_entries; i++) {
        segment->temporal_offset_entries[i] = avio_r8(pb);
        avio_r8(pb);                                        /* KeyFrameOffset */
