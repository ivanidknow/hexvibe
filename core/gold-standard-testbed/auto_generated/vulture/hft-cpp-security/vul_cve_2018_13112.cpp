// Vulnerable: VUL-CVE-2018-13112
11/10/2018 Version 4.3.0
    - Fix maxOS TOS checksum failure (#524)
// --- configure.ac ---
dnl Set version info here!
AC_INIT([tcpreplay],[4.3.0],
    [https://github.com/appneta/tcpreplay/issues],
    [tcpreplay],
// --- utils.c ---
        }

        if (pkthdr->len < pkthdr->caplen) {
...
            fprintf(stderr, "safe_pcap_next_ex ERROR: Invalid packet length in %s:%s() line %d: packet length %u is less than capture length %u\n",
                    file, funcname, line, (*pkthdr)->len, (*pkthdr)->caplen);
            exit(-1);
