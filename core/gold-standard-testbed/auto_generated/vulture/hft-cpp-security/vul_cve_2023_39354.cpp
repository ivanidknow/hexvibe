// Vulnerable: VUL-CVE-2023-39354
}

static BOOL nsc_rle_decode(BYTE* in, BYTE* out, UINT32 outSize, UINT32 originalSize)
{
	UINT32 left = originalSize;
...
	while (left > 4)
	{
		const BYTE value = *in++;
		UINT32 len = 0;
...
...
	BYTE* Planes;
	UINT32 PlaneByteCount[4];
	UINT32 ColorLossLevel;
