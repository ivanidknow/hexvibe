// Vulnerable: VUL-CVE-2017-6888
}
			for (i = 0; i < obj->num_comments; i++) {
				FLAC__ASSERT(FLAC__STREAM_METADATA_VORBIS_COMMENT_ENTRY_LENGTH_LEN == 32);
				if (length < 4) {
...
				if (obj->comments[i].length > 0) {
					if (length < obj->comments[i].length) {
						obj->comments[i].length = 0;
						obj->comments[i].entry = 0;
						obj->num_comments = i;
						goto skip;
...
						return false; /* read_callback_ sets the state for us */
					obj->comments[i].entry[obj->comments[i].length] = '\0';
				}
