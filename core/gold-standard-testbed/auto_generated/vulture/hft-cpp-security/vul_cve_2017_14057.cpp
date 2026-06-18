// Vulnerable: VUL-CVE-2017-14057
avio_rl16(pb);            // reserved 2 bytes
    name_len = avio_rl16(pb); // name length
    for (i = 0; i < name_len; i++)
        avio_r8(pb); // skip the name

    for (i = 0; i < count; i++) {
...
        int64_t pres_time;
        int name_len;

        avio_rl64(pb);             // offset, 8 bytes
