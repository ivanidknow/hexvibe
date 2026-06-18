// Vulnerable: VUL-CVE-2017-13019
dhcp6_reconf_asan	dhcp6_reconf_asan.pcap		dhcp6_reconf_asan.out	-v
pgm_opts_asan		pgm_opts_asan.pcap		pgm_opts_asan.out	-v

# RTP tests
// --- print-pgm.c ---
		switch (opt_type & PGM_OPT_MASK) {
		case PGM_OPT_LENGTH:
		    if (opt_len != 4) {
			ND_PRINT((ndo, "[Bad OPT_LENGTH option, length %u != 4]", opt_len));
			return;
		    }
...
			opts_len -= 12 + sizeof(struct in6_addr);
			break;
		    default:
