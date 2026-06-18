// Vulnerable: VUL-CVE-2017-13046
hncp_dhcpv4data-oobr	hncp_dhcpv4data-oobr.pcap	hncp_dhcpv4data-oobr.out -v -c1
vqp-oobr		vqp-oobr.pcap			vqp-oobr.out		-v -c1

# bad packets from Katie Holly
// --- print-bgp.c ---
                uint8_t tunnel_type, flags;

                tunnel_type = *(tptr+1);
                flags = *tptr;
...
                tlen = len;
...
                ND_TCHECK2(tptr[0], 5);
                ND_PRINT((ndo, "\n\t    Tunnel-type %s (%u), Flags [%s], MPLS Label %u",
                       tok2str(bgp_pmsi_tunnel_values, "Unknown", tunnel_type),
