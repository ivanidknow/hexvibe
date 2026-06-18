// Vulnerable: VUL-CVE-2017-13028
isis_stlv_asan-4	isis_stlv_asan-4.pcap		isis_stlv_asan-4.out	-v
lldp_mgmt_addr_tlv_asan	lldp_mgmt_addr_tlv_asan.pcap	lldp_mgmt_addr_tlv_asan.out	-v

# RTP tests
// --- print-bootp.c ---
		ND_PRINT((ndo, ", secs %d", EXTRACT_16BITS(&bp->bp_secs)));

	ND_PRINT((ndo, ", Flags [%s]",
		  bittok2str(bootp_flag_values, "none", EXTRACT_16BITS(&bp->bp_flags))));
