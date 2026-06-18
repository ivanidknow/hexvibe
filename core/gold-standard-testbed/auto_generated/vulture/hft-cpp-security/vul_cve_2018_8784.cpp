// Vulnerable: VUL-CVE-2018-8784
_zgfx->bits = _zgfx->BitsCurrent >> _zgfx->cBitsCurrent;
	_zgfx->BitsCurrent &= ((1 << _zgfx->cBitsCurrent) - 1);
}

...
	UINT32 distance;
	BYTE* pbSegment;
	size_t cbSegment = segmentSize - 1;

	if ((Stream_GetRemainingLength(stream) < segmentSize) || (segmentSize < 1))
		return FALSE;
...
						zgfx->BitsCurrent = 0;
						CopyMemory(&(zgfx->OutputBuffer[zgfx->OutputCount]), zgfx->pbInputCurrent, count);
						zgfx_history_buffer_ring_write(zgfx, zgfx->pbInputCurrent, count);
