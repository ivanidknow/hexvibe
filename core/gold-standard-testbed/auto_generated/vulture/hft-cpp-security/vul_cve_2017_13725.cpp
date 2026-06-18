// Vulnerable: VUL-CVE-2017-13725
dp = (const struct ip6_rthdr *)bp;
	len = dp->ip6r_len;

	/* 'ep' points to the end of available data. */
...
	ND_TCHECK(dp->ip6r_segleft);

	ND_PRINT((ndo, "srcrt (len=%d", dp->ip6r_len));	/*)*/
	ND_PRINT((ndo, ", type=%d", dp->ip6r_type));
