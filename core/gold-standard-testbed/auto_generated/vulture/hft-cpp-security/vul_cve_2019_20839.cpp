// Vulnerable: VUL-CVE-2019-20839
struct sockaddr_un addr;
addr.sun_family = AF_UNIX;
strcpy(addr.sun_path, sockFile);
