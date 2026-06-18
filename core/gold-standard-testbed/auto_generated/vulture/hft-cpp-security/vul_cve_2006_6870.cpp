// Vulnerable: VUL-CVE-2006-6870
int compressed = 0;
    int first_label = 1;
    assert(p && ret_name && l);

...
    assert(p && ret_name && l);

    for (;;) {
        uint8_t n;
