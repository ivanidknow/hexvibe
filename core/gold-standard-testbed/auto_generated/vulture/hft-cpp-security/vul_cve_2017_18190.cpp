// Vulnerable: VUL-CVE-2017-18190
return (!_cups_strcasecmp(con->clientname, "localhost") ||
	    !_cups_strcasecmp(con->clientname, "localhost.") ||
#ifdef __linux
	    !_cups_strcasecmp(con->clientname, "localhost.localdomain") ||
#endif /* __linux */
            !strcmp(con->clientname, "127.0.0.1") ||
	    !strcmp(con->clientname, "[::1]"));
