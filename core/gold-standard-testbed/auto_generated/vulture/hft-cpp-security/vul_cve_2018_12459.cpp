// Vulnerable: VUL-CVE-2018-12459
/* search next start code */
align_get_bits(gb);

if (s->codec_tag == AV_RL32("WV1F") && show_bits(gb, 24) == 0x575630) {
