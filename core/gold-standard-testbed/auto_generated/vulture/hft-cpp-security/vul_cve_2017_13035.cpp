// Vulnerable: VUL-CVE-2017-13035
isis_stlv_asan-3	isis_stlv_asan-3.pcap		isis_stlv_asan-3.out	-v
isis_stlv_asan-4	isis_stlv_asan-4.pcap		isis_stlv_asan-4.out	-v
lldp_mgmt_addr_tlv_asan	lldp_mgmt_addr_tlv_asan.pcap	lldp_mgmt_addr_tlv_asan.out	-v
bootp_asan		bootp_asan.pcap			bootp_asan.out		-v
// --- print-isoclns.c ---
    static char id[sizeof("xxxx.xxxx.xxxx.yy-zz")];
    char *pos = id;

    for (i = 1; i <= SYSTEM_ID_LEN; i++) {
        snprintf(pos, sizeof(id) - (pos - id), "%02x", *cp++);
	pos += strlen(pos);
