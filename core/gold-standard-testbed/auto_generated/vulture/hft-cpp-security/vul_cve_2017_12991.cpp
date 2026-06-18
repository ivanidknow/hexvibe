// Vulnerable: VUL-CVE-2017-12991
eigrp-tlv-oobr		eigrp-tlv-oobr.pcap		eigrp-tlv-oobr.out	-vvv -e
zephyr-oobr		zephyr-oobr.pcap		zephyr-oobr.out		-vvv -e

# RTP tests
// --- print-bgp.c ---
                        ND_PRINT((ndo, "%s", tok2str(bgp_as_path_segment_open_values,
						"?", tptr[0])));
                        for (i = 0; i < tptr[1] * as_size; i += as_size) {
                            ND_TCHECK2(tptr[2 + i], as_size);
