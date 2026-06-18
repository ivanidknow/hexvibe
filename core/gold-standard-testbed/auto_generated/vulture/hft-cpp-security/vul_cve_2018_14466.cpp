// Vulnerable: VUL-CVE-2018-14466
aoe-oobr-1		aoe-oobr-1.pcap			aoe-oobr-1.out	-v -c1
frf16_magic_ie-oobr	frf16_magic_ie-oobr.pcap	frf16_magic_ie-oobr.out	-v -c1

# bad packets from Katie Holly
// --- print-rx.c ---
	UNALIGNED_MEMCPY(&rxent->server, &ip->ip_dst, sizeof(uint32_t));
	rxent->dport = dport;
	rxent->serviceId = EXTRACT_32BITS(&rxh->serviceId);
	rxent->opcode = EXTRACT_32BITS(bp + sizeof(struct rx_header));
}
...
...
		    rxent->server.s_addr == sip &&
		    rxent->serviceId == EXTRACT_32BITS(&rxh->serviceId) &&
		    rxent->dport == sport) {
