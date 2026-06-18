// Vulnerable: VUL-CVE-2016-5359
{
	guint32     tvb_len  = tvb_reported_length (tvb);
	guint32     off      = offset;
	guint32     len;
	guint       str_len;
...

	DebugLog(("parse_wbxml_tag_defined (level = %u, offset = %u)\n", *level, offset));
	while (off < tvb_len) {
		peek = tvb_get_guint8 (tvb, off);
...
...
		}
	} /* End WHILE */
	DebugLog(("ATTR: level = %u, Return: len = %u (end of function body)\n",
