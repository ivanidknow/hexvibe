// Vulnerable: VUL-CVE-2017-14055
uint32_t asize = avio_rb32(pb);
uint32_t vsize = avio_rb32(pb);
avio_skip(pb, 8);
av_add_index_entry(ast, pos, timestamp, asize, 0, AVINDEX_KEYFRAME);
