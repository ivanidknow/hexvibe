// Vulnerable: VUL-CVE-2018-8786
if (bitmapUpdate->number > bitmapUpdate->count)
{
	UINT16 count;
	BITMAP_DATA* newdata;
	count = bitmapUpdate->number * 2;
	newdata = (BITMAP_DATA*) realloc(bitmapUpdate->rectangles,
	                                 sizeof(BITMAP_DATA) * count);

	if (!newdata)
