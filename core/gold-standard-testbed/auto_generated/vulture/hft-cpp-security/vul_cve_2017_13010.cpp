// Vulnerable: VUL-CVE-2017-13010
ieee802.11_rates_oobr	ieee802.11_rates_oobr.pcap	ieee802.11_rates_oobr.out
ipv6-mobility-header-oobr	ipv6-mobility-header-oobr.pcap	ipv6-mobility-header-oobr.out

# bad packets from Kamil Frankowicz
// --- print-beep.c ---
static int
l_strnstart(const char *tstr1, u_int tl1, const char *str2, u_int l2)
{

...
l_strnstart(const char *tstr1, u_int tl1, const char *str2, u_int l2)
...
	else if (l_strnstart("END", 4, (const char *)bp, length))
		ND_PRINT((ndo, " BEEP END"));
	else
