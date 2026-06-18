// Vulnerable: VUL-CVE-2017-13039
ospf6_decode_v3_asan	ospf6_decode_v3_asan.pcap	ospf6_decode_v3_asan.out -v
ip_ts_opts_asan		ip_ts_opts_asan.pcap		ip_ts_opts_asan.out	-v

# bad packets from Katie Holly
// --- print-isakmp.c ---
static const u_char *
ikev1_attrmap_print(netdissect_options *ndo,
		    const u_char *p, const u_char *ep,
		    const struct attrmap *map, size_t nmap)
{
...
...
			cp = ikev1_attr_print(ndo, cp, (ep < ep2) ? ep : ep2);
	}
	if (ep < ep2)
