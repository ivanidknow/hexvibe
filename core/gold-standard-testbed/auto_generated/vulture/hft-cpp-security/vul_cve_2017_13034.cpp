// Vulnerable: VUL-CVE-2017-13034
pgm_opts_asan_2		pgm_opts_asan_2.pcap		pgm_opts_asan_2.out	-v
pgm_opts_asan_3		pgm_opts_asan_3.pcap		pgm_opts_asan_3.out	-v
vtp_asan		vtp_asan.pcap			vtp_asan.out	-v
vtp_asan-2		vtp_asan-2.pcap			vtp_asan-2.out	-v
// --- print-pgm.c ---
				ip6addr_string(ndo, &ip6->ip6_src),
				ip6addr_string(ndo, &ip6->ip6_dst)));
			return;
		} else {
			ND_PRINT((ndo, "%s > %s: [|pgm]",
...
...
	    bp += (2 * sizeof(uint16_t));
	    switch (EXTRACT_16BITS(bp)) {
	    case AFNUM_INET:
