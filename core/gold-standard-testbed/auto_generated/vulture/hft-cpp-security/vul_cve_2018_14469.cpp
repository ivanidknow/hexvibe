// Vulnerable: VUL-CVE-2018-14469
ip_ts_opts_asan		ip_ts_opts_asan.pcap		ip_ts_opts_asan.out	-v
isakmpv1-attr-oobr	isakmpv1-attr-oobr.pcap		isakmpv1-attr-oobr.out	-v
# The .pcap file is truncated after the 1st packet.
hncp_dhcpv6data-oobr	hncp_dhcpv6data-oobr.pcap	hncp_dhcpv6data-oobr.out -v -c1
// --- print-isakmp.c ---
		case IPSECDOI_NTYPE_REPLAY_STATUS:
			ND_PRINT((ndo," status=("));
			ND_PRINT((ndo,"replay detection %sabled",
				  EXTRACT_32BITS(cp) ? "en" : "dis"));
