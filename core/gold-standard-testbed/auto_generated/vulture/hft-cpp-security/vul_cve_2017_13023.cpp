// Vulnerable: VUL-CVE-2017-13023
icmp6_mobileprefix_asan	icmp6_mobileprefix_asan.pcap	icmp6_mobileprefix_asan.out	-v
ip_printroute_asan	ip_printroute_asan.pcap		ip_printroute_asan.out	-v

# RTP tests
// --- print-mobility.c ---
			}
			/* units of 4 secs */
			ND_PRINT((ndo, "(refresh: %u)",
				EXTRACT_16BITS(&bp[i+2]) << 2));
