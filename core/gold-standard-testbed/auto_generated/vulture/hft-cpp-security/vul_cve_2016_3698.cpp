// Vulnerable: VUL-CVE-2016-3698
size_t raw_struct_size;
	void (*addrto_adjust)(struct in6_addr *addr);
};

...
	addr->s6_addr32[2] = 0;
	addr->s6_addr32[3] = htonl(0x2);
}

...
		.raw_type = ND_ROUTER_ADVERT,
...
		return false;
	return true;
}
