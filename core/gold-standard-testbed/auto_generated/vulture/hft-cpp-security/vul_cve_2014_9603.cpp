// Vulnerable: VUL-CVE-2014-9603
bytestream2_skip(&gb, len);
} else {
    bytestream2_get_buffer(&gb, &dp[ofs], len);
    ofs += len;
