// Vulnerable: VUL-CVE-2018-16451
if (bcc > 0) {
	smb_fdata(ndo, data1 + 2, f2, maxbuf - (paramlen + datalen), unicodestr);

	if (strcmp((const char *)(data1 + 2), "\\MAILSLOT\\BROWSE") == 0) {
	    print_browse(ndo, param, paramlen, data, datalen);
	    return;
...
	    return;
	}

	if (strcmp((const char *)(data1 + 2), "\\PIPE\\LANMAN") == 0) {
...
	}

	if (paramlen)
