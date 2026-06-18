// Vulnerable: VUL-CVE-2020-13114
#define CHECKOVERFLOW(offset,datasize,structsize) (( offset >= datasize) || (structsize > datasize) || (offset > datasize - structsize ))

static void
exif_mnote_data_canon_clear (ExifMnoteDataCanon *n)
...
	ExifShort c;
	size_t i, tcount, o, datao;

	if (!n || !buf || !buf_size) {
...
		}

		/* Tag was successfully parsed */
		++tcount;
