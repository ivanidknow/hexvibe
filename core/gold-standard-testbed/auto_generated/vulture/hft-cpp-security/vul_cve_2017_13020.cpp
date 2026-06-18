// Vulnerable: VUL-CVE-2017-13020
pgm_opts_asan		pgm_opts_asan.pcap		pgm_opts_asan.out	-v
pgm_opts_asan_2		pgm_opts_asan_2.pcap		pgm_opts_asan_2.out	-v

# RTP tests
// --- print-vtp.c ---
	 */

	ND_PRINT((ndo, ", Config Rev %x", EXTRACT_32BITS(tptr)));

...
	while (tptr < (pptr+length)) {

	    len = *tptr;
	    if (len == 0)
