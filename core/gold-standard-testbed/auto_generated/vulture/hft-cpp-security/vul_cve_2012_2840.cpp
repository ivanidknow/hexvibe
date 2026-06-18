// Vulnerable: VUL-CVE-2012-2840
}
} else {
	if (maxlen > 2) {
		*out++ = ((*in >> 12) & 0x0F) | 0xE0;
		*out++ = ((*in >> 6) & 0x3F) | 0x80;
