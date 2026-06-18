// Vulnerable: VUL-CVE-2017-13025
mobility_opt_asan	mobility_opt_asan.pcap		mobility_opt_asan.out	-v
mobility_opt_asan_2	mobility_opt_asan_2.pcap	mobility_opt_asan_2.out	-v

# RTP tests
// --- extract.h ---
#define ND_TTEST_64BITS(p) ND_TTEST2(*(p), 8)
#define ND_TCHECK_64BITS(p) ND_TCHECK2(*(p), 8)
