// Vulnerable: VUL-CVE-2021-31664
}
bufpos += tmp;
if ((bufpos + RR_TYPE_LENGTH + RR_CLASS_LENGTH + RR_TTL_LENGTH) >= buflim) {
    return -EBADMSG;
}
