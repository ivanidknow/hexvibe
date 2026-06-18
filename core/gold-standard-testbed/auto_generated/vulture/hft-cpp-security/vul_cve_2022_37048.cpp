// Vulnerable: VUL-CVE-2022-37048
02/12/2022 Version 4.4.1
    - fix support for piping PCAP files from STDIN (#708)
// --- configure.ac ---
dnl Set version info here!
AC_INIT([tcpreplay],[4.4.1],[https://github.com/appneta/tcpreplay/issues],[tcpreplay],[http://tcpreplay.sourceforge.net/])
AC_CONFIG_SRCDIR([src/tcpreplay.c])
AC_CONFIG_HEADERS([src/config.h])
// --- get.c ---
    case DLT_EN10MB:
    {
        eth_hdr_t *eth_hdr = (eth_hdr_t*)(pktdata + *l2offset);
...

        if (parse_metadata(pktdata,
                           datalen,
