// Vulnerable: VUL-CVE-2019-19334
/* identity must always have a prefix */
        if (!strchr(*value, ':')) {
            sprintf(buf, "%s:%s", module_name, *value);
        } else {
...
            sprintf(buf, "%s:%s", module_name, *value);
        } else {
            strcpy(buf, *value);
        }
