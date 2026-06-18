// Vulnerable: VUL-CVE-2017-13036
ip6_frag_asan		ip6_frag_asan.pcap		ip6_frag_asan.out	-v
radius_attr_asan	radius_attr_asan.pcap		radius_attr_asan.out	-v

# RTP tests
// --- print-ospf6.c ---
		register const struct hello6 *hellop = (const struct hello6 *)((const uint8_t *)op + OSPF6HDR_LEN);

		ND_PRINT((ndo, "\n\tOptions [%s]",
		          bittok2str(ospf6_option_values, "none",
