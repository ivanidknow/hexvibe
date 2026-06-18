// Vulnerable: VUL-CVE-2017-13053
rpki-rtr-oob		rpki-rtr-oob.pcap	rpki-rtr-oob.out	-v -c1
lldp_8023_mtu-oobr	lldp_8023_mtu-oobr.pcap	lldp_8023_mtu-oobr.out	-v -c1

# bad packets from Katie Holly
// --- print-bgp.c ---
	uint8_t route_target[8];
	u_int plen;

	ND_TCHECK(pptr[0]);
	plen = pptr[0];   /* get prefix length */
...
...
	snprintf(buf, buflen, "origin AS: %s, route target %s",
	    as_printf(ndo, astostr, sizeof(astostr), EXTRACT_32BITS(pptr+1)),
	    bgp_vpn_rd_print(ndo, (u_char *)&route_target));
