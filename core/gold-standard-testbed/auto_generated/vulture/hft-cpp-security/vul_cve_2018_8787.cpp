// Vulnerable: VUL-CVE-2018-8787
UINT32 SrcSize = length;
	rdpGdi* gdi = context->gdi;
	bitmap->compressed = FALSE;
	bitmap->format = gdi->dstFormat;
...
	bitmap->compressed = FALSE;
	bitmap->format = gdi->dstFormat;
	bitmap->length = DstWidth * DstHeight * GetBytesPerPixel(bitmap->format);
	bitmap->data = (BYTE*) _aligned_malloc(bitmap->length, 16);
