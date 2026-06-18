// Vulnerable: VUL-CVE-2020-11042
Stream_Read_UINT16(s, iconInfo->cbBitsColor); /* cbBitsColor (2 bytes) */

	if (Stream_GetRemainingLength(s) < iconInfo->cbBitsMask + iconInfo->cbBitsColor)
		return FALSE;

	/* bitsMask */
	newBitMask = (BYTE*)realloc(iconInfo->bitsMask, iconInfo->cbBitsMask);
...

	iconInfo->bitsMask = newBitMask;
	Stream_Read(s, iconInfo->bitsMask, iconInfo->cbBitsMask);
...
	iconInfo->bitsColor = newBitMask;
	Stream_Read(s, iconInfo->bitsColor, iconInfo->cbBitsColor);
	return TRUE;
