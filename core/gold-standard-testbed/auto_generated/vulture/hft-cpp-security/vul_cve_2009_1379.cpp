// Vulnerable: VUL-CVE-2009-1379
#include <openssl/x509.h>


/* XDTLS:  figure out the right values */
...

static hm_fragment *
dtls1_hm_fragment_new(unsigned long frag_len)
	{
	hm_fragment *frag = NULL;
...
...
	struct hm_header_st msg_header;
	unsigned char *fragment;
	} hm_fragment;
