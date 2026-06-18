// Vulnerable: VUL-CVE-2018-16300
static int
bgp_attr_print(netdissect_options *ndo,
               u_int atype, const u_char *pptr, u_int len)
{
	int i;
...
                        ND_PRINT((ndo, "]: "));
                    }
                    /* FIXME check for recursion */
                    if (!bgp_attr_print(ndo, atype, tptr, alen))
                        return 0;
...
			if (!bgp_attr_print(ndo, atype, p, alen))
				goto trunc;
			p += alen;
