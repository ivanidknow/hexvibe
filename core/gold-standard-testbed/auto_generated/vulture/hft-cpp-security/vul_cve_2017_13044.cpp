// Vulnerable: VUL-CVE-2017-13044
# The .pcap file is truncated after the 1st packet.
hncp_dhcpv6data-oobr	hncp_dhcpv6data-oobr.pcap	hncp_dhcpv6data-oobr.out -v -c1

# bad packets from Katie Holly
// --- print-hncp.c ---
    i = 0;
    while (i < length) {
        tlv = cp + i;
        type = (uint8_t)tlv[0];
...
        ND_PRINT((ndo, "%s", tok2str(dh4opt_str, "Unknown", type)));
        ND_PRINT((ndo," (%u)", optlen + 2 ));

        switch (type) {
