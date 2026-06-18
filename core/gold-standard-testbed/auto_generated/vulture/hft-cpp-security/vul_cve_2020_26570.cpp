// Vulnerable: VUL-CVE-2020-26570
}
	else	{
		int rec;
		int offs = 0;
		int rec_len = file->record_length;

		for (rec = 1; ; rec++)   {
...

		for (rec = 1; ; rec++)   {
			rv = sc_read_record(card, rec, *out + offs + 2, rec_len, SC_RECORD_BY_REC_NR);
			if (rv == SC_ERROR_RECORD_NOT_FOUND)   {
