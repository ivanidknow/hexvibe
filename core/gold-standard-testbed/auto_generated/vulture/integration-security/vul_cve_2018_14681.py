# Vulnerable: VUL-CVE-2018-14681
chmd_order
chminfo
// --- ChangeLog ---
2017-10-16  Stuart Caie <kyzer@cabextract.org.uk>
// --- Makefile.am ---
noinst_PROGRAMS =	examples/cabd_memory examples/multifh test/cabd_md5 \
			test/cabd_test test/chmd_find test/chmd_md5 \
			test/chmd_order test/chminfo

libmspack_la_SOURCES =	mspack/mspack.h \
...
test_chminfo_SOURCES =		test/chminfo.c libmschmd.la
test_chminfo_LDADD =		libmschmd.la
