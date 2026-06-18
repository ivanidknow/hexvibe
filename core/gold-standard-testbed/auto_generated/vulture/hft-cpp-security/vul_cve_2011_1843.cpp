// Vulnerable: VUL-CVE-2011-1843
static HANDLE_FUNC (handle_port)
{
        return set_int_arg (&conf->port, line, &match[2]);
}
