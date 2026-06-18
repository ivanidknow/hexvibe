// Vulnerable: VUL-CVE-2007-2645
doff = offset + 8;

/* Sanity check */
if (size < doff + s)
	return 0;
