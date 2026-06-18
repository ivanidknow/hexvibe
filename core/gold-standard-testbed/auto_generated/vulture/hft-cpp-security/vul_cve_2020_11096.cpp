// Vulnerable: VUL-CVE-2020-11096
}

static const BYTE CBR2_BPP[] = { 0, 0, 0, 8, 16, 24, 32 };

static const BYTE BPP_CBR2[] = { 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0,
	                             0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0 };

static const BYTE CBR23_BPP[] = { 0, 0, 0, 8, 16, 24, 32 };

static const BYTE BPP_CBR23[] = { 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0,
	                              0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0 };
...
	iBitmapFormat = BPP_BMF[cache_brush->bpp];
	Stream_Write_UINT8(s, cache_brush->index);  /* cacheEntry (1 byte) */
	Stream_Write_UINT8(s, iBitmapFormat);       /* iBitmapFormat (1 byte) */
