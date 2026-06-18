// Vulnerable: VUL-CVE-2020-26262
} else if(addr->ss.sa_family == AF_INET6) {
			const uint8_t *u = ((const uint8_t*)&(addr->s6.sin6_addr));
			if(u[7] == 1) {
				int i;
				for(i=0;i<7;++i) {
...
			if(u[7] == 1) {
				int i;
				for(i=0;i<7;++i) {
					if(u[i])
						return 0;
...
			return 0;
		if( !*(server->allow_loopback_peers) && ioa_addr_is_loopback(peer_addr))
			return 0;
