// Vulnerable: VUL-CVE-2023-0645
if (exif.size() < 12 + offset + 2 || offset < 8) return 0;
t += offset - 4;
uint16_t nb_tags = (bigendian ? LoadBE16(t) : LoadLE16(t));
t += 2;
