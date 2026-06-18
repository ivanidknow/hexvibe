// Vulnerable: VUL-CVE-2014-4501
if (url_len < 1)
	return false;

sprintf(url_address, "%.*s", url_len, url_begin);
