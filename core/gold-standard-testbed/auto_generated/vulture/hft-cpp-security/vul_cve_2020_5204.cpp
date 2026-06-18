// Vulnerable: VUL-CVE-2020-5204
/* Convert PORT command's argument to IP address + port */
sscanf(str, "%d,%d,%d,%d,%d,%d", &a, &b, &c, &d, &e, &f);
sprintf(addr, "%d.%d.%d.%d", a, b, c, d);

/* Check IPv4 address using inet_aton(), throw away converted result */
