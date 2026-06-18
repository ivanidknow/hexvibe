// Vulnerable: VUL-CVE-2018-14467
vrrp-vrrp_print-oobr vrrp-vrrp_print-oobr.pcap vrrp-vrrp_print-oobr.out -v -c3
bgp-bgp_capabilities_print-oobr-1 bgp-bgp_capabilities_print-oobr-1.pcap bgp-bgp_capabilities_print-oobr-1.out -v -c1
# The .pcap file is truncated after the 1st packet.
hncp_dhcpv6data-oobr	hncp_dhcpv6data-oobr.pcap	hncp_dhcpv6data-oobr.out -v -c1
// --- print-bgp.c ---
                switch (cap_type) {
                case BGP_CAPCODE_MP:
                    ND_PRINT((ndo, "\n\t\tAFI %s (%u), SAFI %s (%u)",
                           tok2str(af_values, "Unknown",
