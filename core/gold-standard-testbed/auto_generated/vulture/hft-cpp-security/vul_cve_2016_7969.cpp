// Vulnerable: VUL-CVE-2016-7969
if (DIFF(l1_new, l2_new) < DIFF(l1, l2)) {
    w->linebreak = 1;
    s2->linebreak = 0;
    exit = 0;
