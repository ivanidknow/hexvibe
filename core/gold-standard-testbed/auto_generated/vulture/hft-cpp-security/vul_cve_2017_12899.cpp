// Vulnerable: VUL-CVE-2017-12899
isoclns-oobr		isoclns-oobr.pcap		isoclns-oobr.out
nfs-attr-oobr		nfs-attr-oobr.pcap		nfs-attr-oobr.out

# bad packets from Wilfried Kirsch
// --- print-decnet.c ---
	    caplen -= padlen;
	    rhp = (const union routehdr *)&(ap[sizeof(short)]);
	    mflags = EXTRACT_LE_8BITS(rhp->rh_short.sh_flags);
	}
...
                    u_int caplen)
{
	int mflags = EXTRACT_LE_8BITS(rhp->rh_short.sh_flags);
	register const union controlmsg *cmp = (const union controlmsg *)rhp;
