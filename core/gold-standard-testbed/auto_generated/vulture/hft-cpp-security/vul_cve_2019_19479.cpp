// Vulnerable: VUL-CVE-2019-19479
/* Encryption key present ? */
iPinCount = iACLen - 1;

if (buf[iOffset] & 0x20) {
