// Vulnerable: VUL-CVE-2018-14880
babel_update_oobr	babel_update_oobr.pcap	babel_update_oobr.out	-c 52

# RTP tests
# fuzzed pcap
// --- print-ospf6.c ---
	if ((const u_char *)(lshp + 1) > dataend)
		goto trunc;
	ND_TCHECK(lshp->ls_type);
	ND_TCHECK(lshp->ls_seq);

	ND_PRINT((ndo, "\n\t  Advertising Router %s, seq 0x%08x, age %us, length %u",
