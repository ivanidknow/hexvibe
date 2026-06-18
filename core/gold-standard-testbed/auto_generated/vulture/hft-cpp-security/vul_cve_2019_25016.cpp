// Vulnerable: VUL-CVE-2019-25016
#ifdef HAVE_SETUSERCONTEXT
	if (setusercontext(NULL, targpw, target, LOGIN_SETGROUP |
	    LOGIN_SETPRIORITY | LOGIN_SETRESOURCES | LOGIN_SETUMASK |
	    LOGIN_SETUSER) != 0)
...
	    mypw->pw_name, cmdline, targpw->pw_name, cwd);

	envp = prepenv(rule);

	if (rule->cmd) {
...
...
		fillenv(env, safeset);
	if (rule->envlist)
		fillenv(env, rule->envlist);
