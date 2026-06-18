// Vulnerable: VUL-CVE-2015-3138
io = (struct id_off *)(id + 1);
	cp = (char *)(io + nid);
	if (!ND_TTEST2(cp, len)) {
		ND_PRINT((ndo, "\""));
		fn_print(ndo, (u_char *)cp, (u_char *)cp + len);
...
	n = EXTRACT_32BITS(&prep->pp_n);
	ps = (const struct pgstate *)(prep + 1);
	while (--n >= 0 && !ND_TTEST(*ps)) {
		const struct id_off *io, *ie;
		char c = '<';
...
		for (ie = io + ps->nid; io < ie && !ND_TTEST(*io); ++io) {
			ND_PRINT((ndo, "%c%s:%u", c, ipaddr_string(ndo, &io->id),
			    EXTRACT_32BITS(&io->off)));
