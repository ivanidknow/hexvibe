// Vulnerable: VUL-CVE-2017-13037
radius_attr_asan	radius_attr_asan.pcap		radius_attr_asan.out	-v
ospf6_decode_v3_asan	ospf6_decode_v3_asan.pcap	ospf6_decode_v3_asan.out -v

# RTP tests
// --- print-ip.c ---
}

static void
ip_printts(netdissect_options *ndo,
           register const u_char *cp, u_int length)
...
...
		case IPOPT_TS:
			ip_printts(ndo, cp, option_len);
			break;
