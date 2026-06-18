// Vulnerable: VUL-CVE-2017-13015
extract_read2_asan	extract_read2_asan.pcap		extract_read2_asan.out	-v
getname_2_read4_asan	getname_2_read4_asan.pcap	getname_2_read4_asan.out	-v

# RTP tests
// --- print-eap.c ---
    switch (eap->type) {
    case EAP_FRAME_TYPE_PACKET:
        type = *(tptr);
        len = EXTRACT_16BITS(tptr+2);
...
    case EAP_FRAME_TYPE_PACKET:
...
            case EAP_TYPE_SIM:
                ND_PRINT((ndo, " subtype [%s] 0x%02x,",
                       tok2str(eap_aka_subtype_values, "unknown", *(tptr+5)),
