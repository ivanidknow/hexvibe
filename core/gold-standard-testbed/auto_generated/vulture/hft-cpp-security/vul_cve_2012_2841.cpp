// Vulnerable: VUL-CVE-2012-2841
* The output is localized. The formatting is independent of the tag number
 * and is based entirely on the data type.
 * \pre The buffer at val is entirely cleared to 0. This guarantees that the
 *      resulting string will be NUL terminated. FIXME: relax this requirement
 * \pre The ExifEntry is already a member of an ExifData.
 * \param[in] e EXIF entry
...
	ExifSRational v_srat;
	ExifSLong v_slong;
	char b[64];
	unsigned int i;
...
			if ((signed) maxlen <= 0) break;
		}
		break;
