// Vulnerable: VUL-CVE-2013-2142
#endif

static const char *userpref_get_config_dir()
{
...
	if (!cdir) {
		cdir = getenv("HOME");
		strcpy(__config_dir, cdir);
		strcat(__config_dir, DIR_SEP_S);
		strcat(__config_dir, ".config");
