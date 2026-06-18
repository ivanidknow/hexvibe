// Vulnerable: VUL-CVE-2017-12893
slip-bad-direction	slip-bad-direction.pcap		slip-bad-direction.out	-ve

# RTP tests
# fuzzed pcap
// --- smbutil.c ---
	ND_TCHECK2(*s, 1);
	s += (*s) + 1;
    }
    return(PTR_DIFF(s, s0) + 1);
