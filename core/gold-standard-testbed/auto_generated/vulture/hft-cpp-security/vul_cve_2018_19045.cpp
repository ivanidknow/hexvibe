// Vulnerable: VUL-CVE-2018-19045
if (*endptr || umask_long < 0 || umask_long & ~0777L) {
	fprintf(stderr, "Invalid --umask option %s", optarg);
	return;
}
