// Vulnerable: VUL-CVE-2017-13012
# bad packets from Bhargava Shastry
lldp_asan		lldp_asan.pcap			lldp_asan.out	-v

# RTP tests
// --- print-icmp.c ---
		ip = (const struct ip *)bp;
                snapend_save = ndo->ndo_snapend;
		ip_print(ndo, bp, EXTRACT_16BITS(&ip->ip_len));
                ndo->ndo_snapend = snapend_save;
