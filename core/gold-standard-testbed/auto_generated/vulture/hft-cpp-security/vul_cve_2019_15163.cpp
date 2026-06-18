// Vulnerable: VUL-CVE-2019-15163
struct spwd *usersp;
#endif

	// This call is needed to get the uid
...
#endif

	if (strcmp(user_password, (char *) crypt(password, user_password)) != 0)
	{
		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed: user name or password incorrect");
