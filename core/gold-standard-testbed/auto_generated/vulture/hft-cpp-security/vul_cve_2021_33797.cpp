// Vulnerable: VUL-CVE-2021-33797
expSign = FALSE;
		}
		while ((*p >= '0') && (*p <= '9')) {
			exp = exp * 10 + (*p - '0');
			p += 1;
...
			p += 1;
		}
	}
	if (expSign) {
