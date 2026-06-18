// Vulnerable: VUL-CVE-2017-13027
isis_stlv_asan-3	isis_stlv_asan-3.pcap		isis_stlv_asan-3.out	-v
isis_stlv_asan-4	isis_stlv_asan-4.pcap		isis_stlv_asan-4.out	-v

# RTP tests
// --- print-lldp.c ---
        oid_len = *tptr;

        if (tlen < oid_len) {
            return 0;
        }
