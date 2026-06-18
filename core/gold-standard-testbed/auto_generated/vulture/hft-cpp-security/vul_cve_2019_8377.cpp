// Vulnerable: VUL-CVE-2019-8377
dbgx(3, "Jumping to next extension header (0x%hhx)", proto);
exthdr = get_ipv6_next((struct tcpr_ipv6_ext_hdr_base *)ptr, len);
proto = exthdr->ip_nh;
ptr = (u_char *)exthdr;
