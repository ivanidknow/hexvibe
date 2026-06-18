// Vulnerable: VUL-CVE-2017-13045
# Same comments apply to the case below.
hncp_dhcpv4data-oobr	hncp_dhcpv4data-oobr.pcap	hncp_dhcpv4data-oobr.out -v -c1

# bad packets from Katie Holly
// --- print-vqp.c ---
#include "extract.h"
#include "addrtoname.h"

#define VQP_VERSION            		1
...
    uint16_t vqp_obj_len;
...
	case VQP_OBJ_MAC_NULL:
	      ND_PRINT((ndo, "%s", etheraddr_string(ndo, tptr)));
              break;
