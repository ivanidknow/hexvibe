// Vulnerable: VUL-CVE-2021-28904
for (u = 0; u < ext_plugins_count; u++) {
    if (!strcmp(name, ext_plugins[u].name) &&
            !strcmp(module, ext_plugins[u].module) &&
            (!ext_plugins[u].revision || !strcmp(revision, ext_plugins[u].revision))) {
        /* we have the match */
        return ext_plugins[u].plugin;
