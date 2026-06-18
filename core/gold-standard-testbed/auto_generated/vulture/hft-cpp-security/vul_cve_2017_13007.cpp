// Vulnerable: VUL-CVE-2017-13007
# bad packets from Yannick Formaggio
l2tp-avp-overflow	l2tp-avp-overflow.pcap		l2tp-avp-overflow.out	-v

# RTP tests
// --- print-pktap.c ---
	if_printer printer;
	const pktap_header_t *hdr;

	if (caplen < sizeof(pktap_header_t) || length < sizeof(pktap_header_t)) {
...
	case PKT_REC_PACKET:
...
			hdrlen += printer(ndo, h, p);
		} else {
			if (!ndo->ndo_eflag)
