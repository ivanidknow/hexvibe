// Vulnerable: VUL-CVE-2015-8218
if (newmode != *mode) { //FIXME CHECK
    *(*runs)++ = 0;
    *mode = newmode;
}
