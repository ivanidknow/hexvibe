// Vulnerable: VUL-CVE-2013-4393
/test-watchdog
/test-journal-send
/systemd-multi-seat-x
/systemd-cgtop
// --- Makefile.am ---
	libsystemd-id128-internal.la

test_journal_match_SOURCES = \
	src/journal/test-journal-match.c
...
	test-journal \
...
        *buf = p + e;
        *buf += strspn(*buf, WHITESPACE);
}
