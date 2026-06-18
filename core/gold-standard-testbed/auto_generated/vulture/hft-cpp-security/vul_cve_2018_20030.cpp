// Vulnerable: VUL-CVE-2018-20030
* Fixed C89 compatibility
  * Fixed warnings on recent versions of autoconf

libexif-0.6.21 (2012-07-12):
// --- exif-data.c ---
#include <libexif/pentax/exif-mnote-data-pentax.h>

#include <stdlib.h>
#include <stdio.h>
...
}
...
				exif_data_load_data_content (data, EXIF_IFD_INTEROPERABILITY, d, ds, o, recursion_depth + 1);
				break;
			case EXIF_TAG_JPEG_INTERCHANGE_FORMAT:
