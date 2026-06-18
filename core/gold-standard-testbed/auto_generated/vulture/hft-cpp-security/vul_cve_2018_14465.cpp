// Vulnerable: VUL-CVE-2018-14465
icmp-icmp_print-oobr-1 icmp-icmp_print-oobr-1.pcap icmp-icmp_print-oobr-1.out -v -c3
icmp-icmp_print-oobr-2 icmp-icmp_print-oobr-2.pcap icmp-icmp_print-oobr-2.out -v -c3
# The .pcap file is truncated after the 1st packet.
hncp_dhcpv6data-oobr	hncp_dhcpv6data-oobr.pcap	hncp_dhcpv6data-oobr.out -v -c1
// --- print-rsvp.c ---
            switch(rsvp_obj_ctype) {
            case RSVP_CTYPE_1:
                ND_PRINT((ndo, "%s  CT: %u",
                       ident,
