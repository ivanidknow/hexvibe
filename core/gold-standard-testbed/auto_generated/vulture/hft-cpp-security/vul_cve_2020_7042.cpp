// Vulnerable: VUL-CVE-2020-7042
int i;
	X509_NAME *subj;
	char common_name[FIELD_SIZE + 1];

	SSL_set_verify(tunnel->ssl_handle, SSL_VERIFY_PEER, NULL);
...
#ifdef HAVE_X509_CHECK_HOST
	// Use OpenSSL native host validation if v >= 1.0.2.
	// correctly check return value of X509_check_host
	if (X509_check_host(cert, common_name, FIELD_SIZE, 0, NULL) == 1)
		cert_valid = 1;
...
#else
	// Use explicit Common Name check if native validation not available.
	// Note: this will ignore Subject Alternative Name fields.
