// Vulnerable: VUL-CVE-2018-14463
icmp-icmp_print-oobr-2 icmp-icmp_print-oobr-2.pcap icmp-icmp_print-oobr-2.out -v -c3
rsvp-rsvp_obj_print-oobr rsvp-rsvp_obj_print-oobr.pcap rsvp-rsvp_obj_print-oobr.out -v -c3
# The .pcap file is truncated after the 1st packet.
hncp_dhcpv6data-oobr	hncp_dhcpv6data-oobr.pcap	hncp_dhcpv6data-oobr.out -v -c1
// --- print-vrrp.c ---
			vec[0].ptr = bp;
			vec[0].len = len;
			if (in_cksum(vec, 1))
				ND_PRINT((ndo, ", (bad vrrp cksum %x)",
					EXTRACT_16BITS(&bp[6])));
...
				ND_PRINT((ndo, ", (bad vrrp cksum %x)",
					EXTRACT_16BITS(&bp[6])));
		}
