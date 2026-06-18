// Vulnerable: VUL-CVE-2020-11526
}

static BOOL _update_read_pointer_color(wStream* s, POINTER_COLOR_UPDATE* pointer_color, BYTE xorBpp)
{
	BYTE* newMask;
...
	BYTE* newMask;
	UINT32 scanlineSize;

	if (!pointer_color)
...
...
	if (!_update_read_pointer_color(s, &pointer_new->colorPtrAttr,
	                                pointer_new->xorBpp)) /* colorPtrAttr */
		goto fail;
