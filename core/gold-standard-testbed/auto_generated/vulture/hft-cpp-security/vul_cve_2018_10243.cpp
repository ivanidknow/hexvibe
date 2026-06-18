// Vulnerable: VUL-CVE-2018-10243
// Ignore whitespace
while ((pos < len) && (isspace((int) data[pos]))) pos++;

if (data[pos] != '"') return HTP_DECLINED;
