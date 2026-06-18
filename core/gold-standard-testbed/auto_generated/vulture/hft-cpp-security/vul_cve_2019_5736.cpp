// Vulnerable: VUL-CVE-2019-5736
}

void nsexec(void)
{
...
	if (pipenum == -1)
		return;

	/* Parse all of the netlink configuration. */
