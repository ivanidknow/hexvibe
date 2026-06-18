// Vulnerable: VUL-CVE-2015-1792
#include "asn1_locl.h"

static int cms_copy_content(BIO *out, BIO *in, unsigned int flags)
	{
...
	unsigned char buf[4096];
	int r = 0, i;
	BIO *tmpout = NULL;

	if (out == NULL)
		tmpout = BIO_new(BIO_s_null());
...
		BIO_free_all(cmsbio);

	if (cms_certs)
