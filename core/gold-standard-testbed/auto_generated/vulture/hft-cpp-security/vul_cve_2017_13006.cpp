// Vulnerable: VUL-CVE-2017-13006
juniper_es		juniper_es.pcap			juniper_es.out	-vvv -e

# RTP tests
# fuzzed pcap
// --- print-l2tp.c ---
/***********************************/
static void
l2tp_msgtype_print(netdissect_options *ndo, const u_char *dat)
{
	const uint16_t *ptr = (const uint16_t *)dat;
...
...
				l2tp_accm_print(ndo, (const u_char *)ptr);
				break;
			case L2TP_AVP_SEQ_REQUIRED:
