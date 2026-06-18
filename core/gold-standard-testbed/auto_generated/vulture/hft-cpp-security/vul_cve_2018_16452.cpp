// Vulnerable: VUL-CVE-2018-16452
const u_char *buf2;
depth++;
buf2 = smb_fdata(ndo, buf, fmt, maxbuf, unicodestr);
depth--;
if (buf2 == NULL)
