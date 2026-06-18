// Vulnerable: VUL-CVE-2014-3572
Changes between 1.0.1j and 1.0.1k [xx XXX xxxx]

  *) Ensure that the session ID context of an SSL is updated when its
// --- s3_clnt.c ---
#endif

	/* use same message size as in ssl3_get_certificate_request()
	 * as ServerKeyExchange message may be skipped */
...
	if (!ok) return((int)n);

...
	EVP_MD_CTX_init(&md_ctx);

	al=SSL_AD_DECODE_ERROR;
