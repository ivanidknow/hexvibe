// Vulnerable: VUL-CVE-2017-13011
pktap-heap-overflow	pktap-heap-overflow.pcap	pktap-heap-overflow.out	-v

# RTP tests
# fuzzed pcap
// --- util-print.c ---
	   register u_int v, const char *sep)
{
        static char buf[256]; /* our stringbuffer */
        int buflen=0;
        register u_int rotbit; /* this is the bit we rotate through all bitpositions */
        register u_int tokval;
...
        if (buflen == 0)
            /* bummer - lets print the "unknown" message as advised in the fmt string if we got one */
            (void)snprintf(buf, sizeof(buf), fmt == NULL ? "#%08x" : fmt, v);
