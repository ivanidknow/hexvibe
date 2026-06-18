// Vulnerable: VUL-CVE-2010-1224
if (!strchr(nm, '.')) {
	if ((sscanf(nm, "%30d", &x) == 1) && (x >= 0) && (x <= 32)) {
		ha->netmask.s_addr = htonl(0xFFFFFFFF << (32 - x));
	} else {
		ast_log(LOG_WARNING, "Invalid CIDR in %s\n", stuff);
