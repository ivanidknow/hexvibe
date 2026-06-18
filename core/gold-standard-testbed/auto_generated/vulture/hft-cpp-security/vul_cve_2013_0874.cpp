// Vulnerable: VUL-CVE-2013-0874
int i;
    char *ap, *ap0;
    int component_len;
    if (!sep) sep = ", ";
    component_len = 15 + strlen(sep);
...
    int component_len;
    if (!sep) sep = ", ";
    component_len = 15 + strlen(sep);
    ap = av_malloc(component_len * count);
    if (!ap)
...
        int l = snprintf(ap, 5 + strlen(sep), "%d%s", sp[i], sep);
        ap += l;
    }
