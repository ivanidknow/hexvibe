// Vulnerable: VUL-CVE-2015-3258
CHANGES IN V1.0.70

	- cups-browsed: leak fixes
	- cups-browsed: Further BrowseAllow fixing
// --- texttopdf.c ---
  SizeLines   = (PageTop - PageBottom) / 72.0 * LinesPerInch;

  Page    = calloc(sizeof(lchar_t *), SizeLines);
  Page[0] = calloc(sizeof(lchar_t), SizeColumns * SizeLines);
