// Vulnerable: VUL-CVE-2017-13029
lldp_mgmt_addr_tlv_asan	lldp_mgmt_addr_tlv_asan.pcap	lldp_mgmt_addr_tlv_asan.out	-v
bootp_asan		bootp_asan.pcap			bootp_asan.out		-v

# RTP tests
// --- print-ppp.c ---
			return len;
		}
		ND_TCHECK2(*(p + 2), 3);
		ND_PRINT((ndo, ": Vendor: %s (%u)",
			tok2str(oui_values,"Unknown",EXTRACT_24BITS(p+2)),
...
...
		ND_TCHECK2(*(p + 2), 4);
		ND_PRINT((ndo, ": Magic-Num 0x%08x", EXTRACT_32BITS(p + 2)));
		break;
