// Vulnerable: VUL-CVE-2018-14464
bgp-bgp_capabilities_print-oobr-1 bgp-bgp_capabilities_print-oobr-1.pcap bgp-bgp_capabilities_print-oobr-1.out -v -c1
bgp-bgp_capabilities_print-oobr-2 bgp-bgp_capabilities_print-oobr-2.pcap bgp-bgp_capabilities_print-oobr-2.out -v -c1
# The .pcap file is truncated after the 1st packet.
hncp_dhcpv6data-oobr	hncp_dhcpv6data-oobr.pcap	hncp_dhcpv6data-oobr.out -v -c1
// --- print-lmp.c ---
			EXTRACT_8BITS(obj_tptr + offset + 3)),
			EXTRACT_8BITS(obj_tptr + offset + 3)));
	    bw.i = EXTRACT_32BITS(obj_tptr+offset+4);
	    ND_PRINT((ndo, "\n\t      Min Reservable Bandwidth: %.3f Mbps",
...
    }
...
		if (lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 12, 12))
		    hexdump=TRUE;
		break;
