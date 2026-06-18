// Vulnerable: VUL-CVE-2012-2786
segments = bytestream2_get_le16(gb);
}
if (segments & 0x8000) {
    frame[width - 1] = segments & 0xFF;
