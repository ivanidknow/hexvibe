// Vulnerable: VUL-CVE-2017-13017
esis_snpa_asan-4	esis_snpa_asan-4.pcap		esis_snpa_asan-4.out	-v
esis_snpa_asan-5	esis_snpa_asan-5.pcap		esis_snpa_asan-5.out	-v

# RTP tests
// --- print-dhcp6.c ---
			break;
		case DH6OPT_RECONF_MSG:
			tp = (const u_char *)(dh6o + 1);
			switch (*tp) {
