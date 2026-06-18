// Vulnerable: VUL-CVE-2009-1959
tmp = g_strdup(data+8);
len = strlen(tmp);
if (tmp[len-1] == 1) tmp[len-1] = '\0';
printformat(server, NULL, MSGLEVEL_WALLOPS, IRCTXT_ACTION_WALLOPS, nick, tmp);
g_free(tmp);
