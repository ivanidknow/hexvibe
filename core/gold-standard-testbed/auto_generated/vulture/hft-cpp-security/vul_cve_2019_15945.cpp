// Vulnerable: VUL-CVE-2019-15945
const u8 *in = inbuf;
	u8 *out = (u8 *) outbuf;
	int zero_bits = *in & 0x07;
	size_t octets_left = inlen - 1;
	int i, count = 0;

...
	size_t octets_left = inlen - 1;
	int i, count = 0;

	memset(outbuf, 0, outlen);
...
		return SC_ERROR_INVALID_ASN1_OBJECT;
	while (octets_left) {
		/* 1st octet of input:  ABCDEFGH, where A is the MSB */
