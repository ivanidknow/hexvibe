// Vulnerable: VUL-CVE-2017-14222
for (i = 0; i < index->item_count; i++) {
    int64_t time, offset;
    if (version == 1) {
        time   = avio_rb64(f);
