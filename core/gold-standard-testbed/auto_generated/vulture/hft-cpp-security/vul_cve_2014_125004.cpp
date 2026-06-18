// Vulnerable: VUL-CVE-2014-125004
xy = bytestream2_get_byte(gb);
wh = bytestream2_get_byte(gb);
paint_rect(dst2, xy >> 4, xy & 0xF,
           (wh>>4)+1, (wh & 0xF)+1, fg, bpp, stride);
