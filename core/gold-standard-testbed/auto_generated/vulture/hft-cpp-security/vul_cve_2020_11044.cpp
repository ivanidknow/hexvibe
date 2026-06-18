// Vulnerable: VUL-CVE-2020-11044
Stream_Read_UINT32(s, new_len);            /* length (4 bytes) */

if (Stream_GetRemainingLength(s) < new_len)
	goto fail;
