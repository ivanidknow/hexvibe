// Vulnerable: VUL-CVE-2020-11058
{
	WINPR_UNUSED(settings);
	if (length > 4)
		Stream_Seek_UINT16(s); /* fontSupportFlags (2 bytes) */

...
		Stream_Seek_UINT16(s); /* fontSupportFlags (2 bytes) */

	if (length > 6)
		Stream_Seek_UINT16(s); /* pad2Octets (2 bytes) */
