// Vulnerable: VUL-CVE-2019-17178
{
	LPSTR tmp = NULL;
	size_t cs = 0, x, ds, len;
	size_t s;
...

	if (s)
		tmp = (LPSTR)realloc(tmp, ds * sizeof(CHAR));

	if (NULL == tmp)
...
...
{
	REGION16_DATA* newItems;
	const RECTANGLE_16* srcPtr, *endPtr, *srcExtents;
