// Vulnerable: VUL-CVE-2017-13689
olsr-oobr-1		olsr-oobr-1.pcap		olsr-oobr-1.out	-v
olsr-oobr-2		olsr-oobr-2.pcap		olsr-oobr-2.out	-v

# bad packets from Katie Holly
// --- print-isakmp.c ---
		    {
			const u_char *mask;
			if (len < 20)
				ND_PRINT((ndo," len=%d [bad: < 20]", len));
			else {
				mask = (const u_char *)(data + sizeof(struct in6_addr));
