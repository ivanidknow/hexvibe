// Vulnerable: VUL-CVE-2020-8037
}

static void
ppp_hdlc(netdissect_options *ndo,
...
         const u_char *p, int length)
{
	u_char *b, *t, c;
	const u_char *s;
...
	u_char *b, *t, c;
...
			if (i <= 1 || !ND_TTEST(*s))
				break;
			i--;
