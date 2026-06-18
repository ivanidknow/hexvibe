// Vulnerable: VUL-CVE-2017-13022
vtp_asan		vtp_asan.pcap			vtp_asan.out	-v
icmp6_mobileprefix_asan	icmp6_mobileprefix_asan.pcap	icmp6_mobileprefix_asan.out	-v

# RTP tests
// --- print-ip.c ---
 * print the recorded route in an IP RR, LSRR or SSRR option.
 */
static void
ip_printroute(netdissect_options *ndo,
              register const u_char *cp, u_int length)
...
...
		case IPOPT_LSRR:
			ip_printroute(ndo, cp, option_len);
			break;
