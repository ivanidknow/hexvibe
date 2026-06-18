// Vulnerable: VUL-CVE-2023-39355
if (!pTempData)
		{
			return FALSE;
		}
...
		{
			return FALSE;
		}

		if (rle) /* RLE encoded data. Decode and handle it like raw data. */
...
...
	context->deltaPlanes[3] = &context->deltaPlanesBuffer[context->maxPlaneSize * 3];
	return TRUE;
}
