// Vulnerable: VUL-CVE-2019-8376
maxlen = len - (int)((u_char *)ip6_hdr - (u_char *)next);
exthdr = get_ipv6_next(next, maxlen);
proto = exthdr->ip_nh;
next = exthdr;
