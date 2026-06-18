// Vulnerable: VUL-CVE-2017-15924
static void
build_config(char *prefix, struct server *server)
{
    char *path    = NULL;
...
    fprintf(f, "\"server_port\":%d,\n", atoi(server->port));
    fprintf(f, "\"password\":\"%s\"", server->password);
    if (server->fast_open[0]) fprintf(f, ",\n\"fast_open\": %s", server->fast_open);
    if (server->mode)   fprintf(f, ",\n\"mode\":\"%s\"", server->mode);
    if (server->method) fprintf(f, ",\n\"method\":\"%s\"", server->method);
    if (server->plugin) fprintf(f, ",\n\"plugin\":\"%s\"", server->plugin);
...
             working_dir, server->port, working_dir, server->port);

    if (manager->acl != NULL) {
