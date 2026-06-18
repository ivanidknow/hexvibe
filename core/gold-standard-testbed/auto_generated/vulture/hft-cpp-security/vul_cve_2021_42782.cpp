// Vulnerable: VUL-CVE-2021-42782
u8        rbuf[SC_MAX_APDU_BUFFER_SIZE];
        int       r;
	const u8  *p = rbuf, *q;
	size_t    len, tlen = 0, ilen = 0;

...

	while (len != 0) {
		p = sc_asn1_find_tag(card->ctx, p, len, 0xe1, &tlen);
		if (p == NULL)
			return 0;
...
		q = sc_asn1_find_tag(card->ctx, p, tlen, 0x01, &ilen);
		if (q == NULL || ilen != 4)
			return 0;
