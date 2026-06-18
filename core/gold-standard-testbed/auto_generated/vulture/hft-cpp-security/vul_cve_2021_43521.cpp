// Vulnerable: VUL-CVE-2021-43521
pline = line;
} else {
	for (p--; isspace((int)*p); --p)
		/*EMPTY*/;
	p++;
