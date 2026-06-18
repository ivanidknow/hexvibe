// Vulnerable: VUL-CVE-2009-3895
exif_entry_fix (ExifEntry *e)
{
	unsigned int i;
	ExifByteOrder o;
	ExifRational r;
...
				exif_format_get_name (e->format),
				exif_format_get_name (EXIF_FORMAT_SHORT));
			o = exif_data_get_byte_order (e->parent->parent);
			for (i = 0; i < e->components; i++)
...
...
			e->data = exif_entry_realloc (e, e->data, e->size);
			break;
		case EXIF_FORMAT_SHORT:
