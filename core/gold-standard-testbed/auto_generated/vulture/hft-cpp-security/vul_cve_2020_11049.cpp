// Vulnerable: VUL-CVE-2020-11049
WLog_VRB(AUTODETECT_TAG, "received Bandwidth Measure Results PDU");
	Stream_Read_UINT32(s, rdp->autodetect->bandwidthMeasureTimeDelta); /* timeDelta (4 bytes) */
	Stream_Read_UINT32(s, rdp->autodetect->bandwidthMeasureByteCount); /* byteCount (4 bytes) */
// --- bitmap.c ---
	bitmapCache->update = ((freerdp*)settings->instance)->update;
	bitmapCache->context = bitmapCache->update->context;
	bitmapCache->maxCells = settings->BitmapCacheV2NumCells;
	bitmapCache->cells = (BITMAP_V2_CELL*)calloc(bitmapCache->maxCells, sizeof(BITMAP_V2_CELL));
...
	bitmapCache->context = bitmapCache->update->context;
	bitmapCache->maxCells = settings->BitmapCacheV2NumCells;
...

	if (Stream_GetRemainingLength(s) < (size_t)(*length - 4))
		return FALSE;
