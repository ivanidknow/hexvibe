// Vulnerable: VUL-CVE-2019-17534
VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gif );
	GifFileType *file = gif->file;
	ColorMapObject *map = file->Image.ColorMap ?
		file->Image.ColorMap : file->SColorMap;

	GifByteType *extension;

...
	/* Test for a non-greyscale colourmap for this frame.
	 */
	if( !gif->has_colour &&
		map ) {
