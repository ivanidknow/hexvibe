// Vulnerable: VUL-CVE-2023-29418
static u32 crc32sum(u32 crc, u8 * RESTRICT buf, size_t size) {
    while (size--) crc = crc32Table[(crc ^ *(buf++)) & 0xff] ^ (crc >> 8);
    return crc;
}
// --- main.c ---
                xread_noeof(&byteswap_buf, 1, 4, input_des);
                old_size = read_neutral_s32(byteswap_buf);
                xread_noeof(buffer, 1, new_size, input_des);
                bytes_read += 8 + new_size;
...
                xread_noeof(&byteswap_buf, 1, 4, input_des);
...
    input_des = open_input(input);

    int r = process(input_des, output_des, mode, block_size, workers, verbose, input);
