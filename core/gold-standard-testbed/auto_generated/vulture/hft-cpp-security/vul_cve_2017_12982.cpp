// Vulnerable: VUL-CVE-2017-12982
header->biBitCount  = (OPJ_UINT16)getc(IN);
header->biBitCount |= (OPJ_UINT16)((OPJ_UINT32)getc(IN) << 8);

if (header->biSize >= 40U) {
