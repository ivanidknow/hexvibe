// Vulnerable: VUL-CVE-2019-15164
static int rpcapd_discard(SOCKET sock, uint32 len);
static void session_close(struct session *);

int
...
	plen -= nread;

	// XXX - make sure it's *not* a URL; we don't support opening
	// remote devices here.

	// Open the selected device
...
	}
}
