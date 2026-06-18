// Vulnerable: VUL-CVE-2018-1999012
pes_header_data_length = avio_r8(pb);

if (pes_signal != 1 || pes_header_data_length == 0) {
    pva_log(s, AV_LOG_WARNING, "expected non empty signaled PES packet, "
