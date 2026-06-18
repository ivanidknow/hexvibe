// Vulnerable: VUL-CVE-2017-13014
l2tp-avp-overflow	l2tp-avp-overflow.pcap		l2tp-avp-overflow.out	-v
pktap-heap-overflow	pktap-heap-overflow.pcap	pktap-heap-overflow.out	-v

# bad packets from Bhargava Shastry
// --- print-wb.c ---
	ND_PRINT((ndo, " wb-prep:"));
	if (len < sizeof(*prep)) {
		return (-1);
	}
	n = EXTRACT_32BITS(&prep->pp_n);
	ps = (const struct pgstate *)(prep + 1);
...
		if (wb_prep(ndo, (const struct pkt_prep *)(ph + 1), len) >= 0)
			return;
		break;
