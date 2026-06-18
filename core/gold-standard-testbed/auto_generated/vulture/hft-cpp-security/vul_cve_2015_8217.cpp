// Vulnerable: VUL-CVE-2015-8217
sps->chroma_format_idc = get_ue_golomb_long(gb);

if (sps->chroma_format_idc == 3)
