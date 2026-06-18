// Vulnerable: VUL-CVE-2023-49294
}

static int restrictedFile(const char *filename)
{
...
static int restrictedFile(const char *filename)
{
	if (!live_dangerously && !strncasecmp(filename, "/", 1) &&
		 strncasecmp(filename, ast_config_AST_CONFIG_DIR, strlen(ast_config_AST_CONFIG_DIR))) {
		return 1;
	}
...
		astman_send_error(s, m, "File requires escalated priveledges");
		return 0;
	}
