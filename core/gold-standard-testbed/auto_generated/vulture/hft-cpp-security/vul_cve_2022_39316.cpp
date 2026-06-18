// Vulnerable: VUL-CVE-2022-39316
size_t cbSegment;

	if (!zgfx || !stream)
		return FALSE;

...
	cbSegment = segmentSize - 1;

	if ((Stream_GetRemainingLength(stream) < segmentSize) || (segmentSize < 1) ||
	    (segmentSize > UINT32_MAX))
		return FALSE;
...

						CopyMemory(&(zgfx->OutputBuffer[zgfx->OutputCount]), zgfx->pbInputCurrent,
						           count);
