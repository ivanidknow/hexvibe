# Vulnerable: VUL-CVE-2017-13047
bgp_mvpn_6_and_7	bgp_mvpn_6_and_7.pcap		bgp_mvpn_6_and_7.out	-v -c1
rsvp_fast_reroute-oobr	rsvp_fast_reroute-oobr.pcap	rsvp_fast_reroute-oobr.out -v -c1

# bad packets from Katie Holly
// --- esis_snpa_asan-3.out ---
	redirect (6), v: 1, checksum: 0x0300 (incorrect should be 0xbce5), holding time: 21480s, length indicator: 17
	  ec.ff00.00
	  SNPA (length: 0): <empty>
