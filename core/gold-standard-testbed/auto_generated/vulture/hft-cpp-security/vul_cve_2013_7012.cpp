// Vulnerable: VUL-CVE-2013-7012
s->tile_offset_y  = bytestream2_get_be32u(&s->g); // YT0Siz
ncomponents       = bytestream2_get_be16u(&s->g); // CSiz

if (ncomponents <= 0) {
