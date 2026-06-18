// Vulnerable: VUL-CVE-2023-40589
{
	UINT32 index;
	UINT32 bits;
	INT32 nbits;
	const BYTE* SrcPtr;
	const BYTE* SrcEnd;
	UINT16 Mask;
	BYTE Literal;
	UINT32 IndexLEC;
...
	UINT32 IndexLEC;
...

		if (((((1 << LOMBitsLUT[i]) - 1) & (k - 2)) + LOMBaseLUT[i]) != k)
			return -1;
