// Vulnerable: VUL-CVE-2020-12740
maxlen = len - (int)((u_char *)ip6_hdr - (u_char *)next);
exthdr = get_ipv6_next(next, maxlen);
proto = exthdr->ip_nh;
next = exthdr;
