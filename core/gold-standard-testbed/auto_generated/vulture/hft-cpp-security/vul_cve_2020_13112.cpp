// Vulnerable: VUL-CVE-2020-13112
#include <libexif/exif-utils.h>
#include <libexif/exif-data.h>

static void
...
	}
	datao = 6 + n->offset;
	if ((datao + 2 < datao) || (datao + 2 < 2) || (datao + 2 > buf_size)) {
		exif_log (ne->log, EXIF_LOG_CODE_CORRUPT_DATA,
			  "ExifMnoteCanon", "Short MakerNote");
...
...
				(dataofs + s > buf_size)) {
				exif_log (en->log, EXIF_LOG_CODE_DEBUG,
						  "ExifMnoteDataPentax", "Tag data past end "
