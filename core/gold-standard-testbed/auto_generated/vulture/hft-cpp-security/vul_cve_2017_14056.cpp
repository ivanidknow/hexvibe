// Vulnerable: VUL-CVE-2017-14056
/** read offset and size tables */
    for(i=0; i < frame_count;i++)
        chunk_size[i] = avio_rl32(pb);
    for(i=0; i < frame_count;i++)
...
    for(i=0; i < frame_count;i++)
        chunk_size[i] = avio_rl32(pb);
    for(i=0; i < frame_count;i++)
        chunk_offset[i] = avio_rl32(pb);
    for(i=0; i < frame_count;i++)
...
...
        audio_size[i] = avio_rl32(pb) & 0xFFFF;

    /** build the sample index */
