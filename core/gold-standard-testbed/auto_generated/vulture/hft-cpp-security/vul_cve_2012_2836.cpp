// Vulnerable: VUL-CVE-2012-2836
void
exif_data_load_data (ExifData *data, const unsigned char *d_orig,
		     unsigned int ds_orig)
{
	unsigned int l;
...
	ExifShort n;
	const unsigned char *d = d_orig;
	unsigned int ds = ds_orig, len;

	if (!data || !data->priv || !d || !ds)
...
	interpret_maker_note(data, d, ds);

	/* Fixup tags if requested */
