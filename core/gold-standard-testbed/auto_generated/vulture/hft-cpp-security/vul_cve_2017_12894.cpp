// Vulnerable: VUL-CVE-2017-12894
# bad packets from Otto Airamo and Antti Levomäki
nbns-valgrind		nbns-valgrind.pcap		nbns-valgrind.out	-vvv -e

# RTP tests
// --- addrtoname.c ---
	u_char *e_nsap;			/* used only for nsaptable[] */
#define e_bs e_nsap			/* for bytestringtable */
	struct enamemem *e_nxt;
};
...
static struct enamemem enametable[HASHNAMESIZE];
...
	*cp = '\0';
	return (tp->e_name);
}
