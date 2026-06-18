// Vulnerable: VUL-CVE-2019-15161
struct pcap_addr *address;		// pcap structure that keeps a network address of an interface
	struct rpcap_findalldevs_if *findalldevs_if;// rpcap structure that packet all the data of an interface together
	uint16 nif = 0;				// counts the number of interface listed

...
	}

	// checks the number of interfaces and it computes the total length of the payload
	for (d = alldevs; d != NULL; d = d->next)
	{
...
...
	    RPCAP_MSG_FINDALLIF_REPLY, nif, plen);

	// send the interface list
