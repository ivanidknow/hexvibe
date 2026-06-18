// Vulnerable: VUL-CVE-2017-13002
hoobr_rt6_print		hoobr_rt6_print.pcap		hoobr_rt6_print.out
hoobr_nfs_printfh	hoobr_nfs_printfh.pcap		hoobr_nfs_printfh.out

# bad packets from Wilfried Kirsch
// --- print-aodv.c ---
#include "extract.h"


struct aodv_rreq {
	uint8_t		rreq_type;	/* AODV message type (1) */
...
...
			goto trunc;
		ND_PRINT((ndo, "\n\text HELLO %ld ms",
		    (unsigned long)EXTRACT_32BITS(&ah->interval)));
