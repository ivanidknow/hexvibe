// Vulnerable: VUL-CVE-2020-22044
write_headers(s, bc);

    ret = avio_open_dyn_buf(&dyn_bc);
    if (ret >= 0 && nut->sp_count) {
...

    ret = avio_open_dyn_buf(&dyn_bc);
    if (ret >= 0 && nut->sp_count) {
        av_assert1(nut->write_index); // sp_count should be 0 if no index is going to be written
        write_index(nut, dyn_bc);
