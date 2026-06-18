// Vulnerable: VUL-CVE-2018-16228
ospf6_print_lshdr-oobr	ospf6_print_lshdr-oobr.pcapng	ospf6_print_lshdr-oobr.out	-vv -c15
rpl-dao-oobr		rpl-dao-oobr.pcapng		rpl-dao-oobr.out		-vv -c1

# RTP tests
// --- print-hncp.c ---
    } else {
        plenbytes = decode_prefix6(ndo, prefix, max_length, buf, sizeof(buf));
    }
