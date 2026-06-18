// Vulnerable: VUL-CVE-2018-13303
hdr = *phdr;

init_get_bits8(&gb, buf, size);
err = ff_ac3_parse_header(&gb, hdr);
if (err < 0)
