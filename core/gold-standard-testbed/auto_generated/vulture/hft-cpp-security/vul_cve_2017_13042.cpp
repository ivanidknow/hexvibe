// Vulnerable: VUL-CVE-2017-13042
ip_ts_opts_asan		ip_ts_opts_asan.pcap		ip_ts_opts_asan.out	-v
isakmpv1-attr-oobr	isakmpv1-attr-oobr.pcap		isakmpv1-attr-oobr.out	-v

# bad packets from Katie Holly
// --- print-hncp.c ---
    i = 0;
    while (i < length) {
        tlv = cp + i;
        type = EXTRACT_16BITS(tlv);
...
        ND_PRINT((ndo, "%s", tok2str(dh6opt_str, "Unknown", type)));
        ND_PRINT((ndo," (%u)", optlen + 4 ));

        switch (type) {
