// Vulnerable: VUL-CVE-2021-30219
parselet(s, &val);
ruleaddvar(r, var, val);
if (strcmp(var, "command") == 0)
	hascommand = true;
