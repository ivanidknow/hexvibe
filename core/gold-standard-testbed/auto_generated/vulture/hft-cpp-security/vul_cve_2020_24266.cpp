// Vulnerable: VUL-CVE-2020-24266
case DLT_JUNIPER_ETHER:
    if (datalen >= 5) {
        l2_len = -1;
        break;
