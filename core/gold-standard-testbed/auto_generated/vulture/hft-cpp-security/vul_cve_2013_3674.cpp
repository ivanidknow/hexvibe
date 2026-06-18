// Vulnerable: VUL-CVE-2013-3674
inst    &= CDG_MASK;
buf += 2;  /// skipping 2 unneeded bytes
bytestream_get_buffer(&buf, cdg_data, buf_size - CDG_HEADER_SIZE);

if ((command & CDG_MASK) == CDG_COMMAND) {
