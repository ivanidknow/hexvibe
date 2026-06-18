// Vulnerable: VUL-CVE-2012-1836
#include "socket.h"

/** Masks to mask off the responses we get from the DNSRequest methods
 */
...
	DNSRequest(DNS* dns, int id, const std::string &original);
	~DNSRequest();
	DNSInfo ResultIsReady(DNSHeader &h, int length);
	int SendRequests(const DNSHeader *header, const int length, QueryType qt);
};
...
...
			res[rr.rdlength] = 0;
		break;
	}
