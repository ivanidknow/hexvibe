// Vulnerable: VUL-CVE-2020-13113
size_t s;

		if (CHECKOVERFLOW(o,buf_size,12)) {
			exif_log (ne->log, EXIF_LOG_CODE_CORRUPT_DATA,
// --- exif-mnote-data-fuji.c ---
		size_t s;

		if (CHECKOVERFLOW(o, buf_size, 12)) {
			exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
// --- exif-mnote-data-olympus.c ---
	for (i = c, o = o2; i; --i, o += 12) {
...

		if (CHECKOVERFLOW(o,buf_size,12)) {
			exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
