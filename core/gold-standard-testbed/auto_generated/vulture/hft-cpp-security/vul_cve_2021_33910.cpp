// Vulnerable: VUL-CVE-2021-33910
int unit_name_path_escape(const char *f, char **ret) {
        char *p, *s;

        assert(f);
...
        assert(ret);

        p = strdupa(f);
        if (!p)
                return -ENOMEM;
...
...
        /* Refuse this if this got too long or for some other reason didn't result in a valid name */
        if (!unit_name_is_valid(s, UNIT_NAME_INSTANCE))
                return -EINVAL;
