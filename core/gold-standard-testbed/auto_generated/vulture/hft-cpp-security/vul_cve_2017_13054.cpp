// Vulnerable: VUL-CVE-2017-13054
rsvp_uni-oobr-3	rsvp_uni-oobr-3.pcap	rsvp_uni-oobr-3.out	-v -c3
rpki-rtr-oob		rpki-rtr-oob.pcap	rpki-rtr-oob.out	-v -c1

# bad packets from Katie Holly
// --- print-lldp.c ---
    case LLDP_PRIVATE_8023_SUBTYPE_MTU:
        ND_PRINT((ndo, "\n\t    MTU size %u", EXTRACT_16BITS(tptr + 4)));
        break;
