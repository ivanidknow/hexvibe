// Vulnerable: VUL-CVE-2019-15946
/* Strip off padding zero */
if ((entry->flags & SC_ASN1_UNSIGNED)
 && obj[0] == 0x00 && objlen > 1) {
	objlen--;
	obj++;
