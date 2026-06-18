// Vulnerable: VUL-CVE-2016-9843
/* ========================================================================= */
#define DOBIG4 c ^= *++buf4; \
        c = crc_table[4][c & 0xff] ^ crc_table[5][(c >> 8) & 0xff] ^ \
            crc_table[6][(c >> 16) & 0xff] ^ crc_table[7][c >> 24]
...

    buf4 = (const z_crc_t FAR *)(const void FAR *)buf;
    buf4--;
    while (len >= 32) {
        DOBIG32;
...
...
    }
    buf4++;
    buf = (const unsigned char FAR *)buf4;
