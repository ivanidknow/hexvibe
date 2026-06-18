// Vulnerable: VUL-CVE-2019-15167
rsvp-rsvp_obj_print-oobr rsvp-rsvp_obj_print-oobr.pcap rsvp-rsvp_obj_print-oobr.out -v -c3
vrrp-vrrp_print-oobr vrrp-vrrp_print-oobr.pcap vrrp-vrrp_print-oobr.out -v -c3
bgp-bgp_capabilities_print-oobr-1 bgp-bgp_capabilities_print-oobr-1.pcap bgp-bgp_capabilities_print-oobr-1.out -v -c1
bgp-bgp_capabilities_print-oobr-2 bgp-bgp_capabilities_print-oobr-2.pcap bgp-bgp_capabilities_print-oobr-2.out -v -c1
// --- print-vrrp.c ---
			uint16_t cksum = nextproto4_cksum(ndo, (const struct ip *)bp2, bp,
				len, len, IPPROTO_VRRP);
			if (cksum)
				ND_PRINT((ndo, ", (bad vrrp cksum %x)",
					EXTRACT_16BITS(&bp[6])));
...
				ND_PRINT((ndo, ", (bad vrrp cksum %x)",
					EXTRACT_16BITS(&bp[6])));
		}
