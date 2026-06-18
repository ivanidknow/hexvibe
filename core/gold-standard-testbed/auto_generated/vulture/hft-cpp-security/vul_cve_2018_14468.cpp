// Vulnerable: VUL-CVE-2018-14468
isakmp-various-oobr	isakmp-various-oobr.pcap	isakmp-various-oobr.out	-v
aoe-oobr-1		aoe-oobr-1.pcap			aoe-oobr-1.out	-v -c1

# bad packets from Katie Holly
// --- print-fr.c ---
            case MFR_CTRL_IE_MAGIC_NUM:
                ND_PRINT((ndo, "0x%08x", EXTRACT_32BITS(tptr)));
                break;
