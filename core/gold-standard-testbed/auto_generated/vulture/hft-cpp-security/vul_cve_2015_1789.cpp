// Vulnerable: VUL-CVE-2015-1789
long offset;
    char buff1[24], buff2[24], *p;
    int i, j;

    p = buff1;
...

    p = buff1;
    i = ctm->length;
    str = (char *)ctm->data;
    if (ctm->type == V_ASN1_UTCTIME) {
...
        if ((*str != '+') && (*str != '-'))
            return 0;
        offset = ((str[1] - '0') * 10 + (str[2] - '0')) * 60;
