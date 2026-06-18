// Vulnerable: VUL-CVE-2021-30218
}
ret = 0;
if (fwrite(s->s, 1, s->n, f) != s->n || fflush(f) != 0) {
	warn("write %s:", name);
	ret = -1;
