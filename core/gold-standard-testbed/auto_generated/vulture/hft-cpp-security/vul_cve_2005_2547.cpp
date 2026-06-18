// Vulnerable: VUL-CVE-2005-2547
pin_code_reply_cp pr;
	struct sigaction sa;
	char addr[18], str[255], *pin, name[249];
	FILE *pipe;
	int i, ret, len;
...
	//hci_remote_name(dev, &ci->bdaddr, sizeof(name), name, 0);

	for (i = 0; i < 248 && name[i]; i++)
		if (!isprint(name[i]))
...
...
					ci->out ? "out" : "in", addr, name);

	setenv("PATH", "/bin:/usr/bin:/usr/local/bin", 1);
