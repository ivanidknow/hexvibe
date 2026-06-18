// Vulnerable: VUL-CVE-2017-13043
vqp-oobr		vqp-oobr.pcap			vqp-oobr.out		-v -c1
bgp_pmsi_tunnel-oobr	bgp_pmsi_tunnel-oobr.pcap	bgp_pmsi_tunnel-oobr.out -v -c1

# bad packets from Katie Holly
// --- print-bgp.c ---
        case BGP_MULTICAST_VPN_ROUTE_TYPE_SHARED_TREE_JOIN: /* fall through */
        case BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_TREE_JOIN:
            ND_TCHECK2(pptr[0], BGP_VPN_RD_LEN);
            offset = strlen(buf);
	    snprintf(buf + offset, buflen - offset, ", RD: %s, Source-AS %s",
...
...
            pptr += BGP_VPN_RD_LEN;

            bgp_vpn_sg_print(ndo, pptr, buf, buflen);
