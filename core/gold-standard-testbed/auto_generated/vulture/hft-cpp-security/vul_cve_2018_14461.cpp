// Vulnerable: VUL-CVE-2018-14461
isakmpv1-attr-oobr	isakmpv1-attr-oobr.pcap		isakmpv1-attr-oobr.out	-v
isakmp-ikev1_n_print-oobr isakmp-ikev1_n_print-oobr.pcap isakmp-ikev1_n_print-oobr.out -v -c3
# The .pcap file is truncated after the 1st packet.
hncp_dhcpv6data-oobr	hncp_dhcpv6data-oobr.pcap	hncp_dhcpv6data-oobr.out -v -c1
// --- print-ldp.c ---
#include "l2vpn.h"
#include "af.h"

/*
...

...
    ND_PRINT((ndo, "\n\t\t packet exceeded snapshot"));
    return 0;
}
