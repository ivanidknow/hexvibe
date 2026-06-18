// Vulnerable: VUL-CVE-2017-12998
isis-areaaddr-oobr-1	isis-areaaddr-oobr-1.pcap	isis-areaaddr-oobr-1.out		-vvv -e
isis-areaaddr-oobr-2	isis-areaaddr-oobr-2.pcap	isis-areaaddr-oobr-2.out		-vvv -e

# RTP tests
// --- print-isoclns.c ---
        processed++;
    } else if (afi == AF_INET6) {
        if (!ND_TTEST2(*tptr, 1)) /* fetch status & prefix_len byte */
            return (0);
        status_byte=*(tptr++);
