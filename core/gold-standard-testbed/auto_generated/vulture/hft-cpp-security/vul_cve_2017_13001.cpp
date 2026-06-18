// Vulnerable: VUL-CVE-2017-13001
hoobr_lookup_nsap	hoobr_lookup_nsap.pcap		hoobr_lookup_nsap.out
hoobr_rt6_print		hoobr_rt6_print.pcap		hoobr_rt6_print.out

# bad packets from Wilfried Kirsch
// --- print-nfs.c ---
	if (sfsname) {
		/* file system ID is ASCII, not numeric, for this server OS */
		static char temp[NFSX_V3FHMAX+1];

		/* Make sure string is null-terminated */
...
...
		temp[sizeof(temp) - 1] = '\0';
		/* Remove trailing spaces */
		spacep = strchr(temp, ' ');
