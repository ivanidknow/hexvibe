// Vulnerable: VUL-CVE-2020-11045
if (!(bitmapData->flags & NO_BITMAP_COMPRESSION_HDR))
{
	Stream_Read_UINT16(s,
	                   bitmapData->cbCompFirstRowSize); /* cbCompFirstRowSize (2 bytes) */
