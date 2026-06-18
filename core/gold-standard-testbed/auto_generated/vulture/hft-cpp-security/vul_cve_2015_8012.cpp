// Vulnerable: VUL-CVE-2015-8012
#include <errno.h>
#include <arpa/inet.h>
#include <assert.h>

static int
...
									sizeof(struct in_addr), 0);
						if (mgmt == NULL) {
							assert(errno == ENOMEM);
							log_warn("cdp", "unable to allocate memory for management address");
							goto malformed;
...
	assert(addrsize <= LLDPD_MGMT_MAXADDRSIZE);
	memcpy(&mgmt->m_addr, addrptr, addrsize);
	mgmt->m_addrsize = addrsize;
