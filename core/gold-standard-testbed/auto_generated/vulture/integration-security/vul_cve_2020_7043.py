# Vulnerable: VUL-CVE-2020-7043
src/ipv4.h src/log.c src/log.h src/tunnel.c \
		       src/tunnel.h src/main.c src/ssl.h src/xml.c \
		       src/xml.h src/userinput.c src/userinput.h
openfortivpn_CFLAGS = -Wall -pedantic -std=gnu99
openfortivpn_CPPFLAGS = -DSYSCONFDIR=\"$(sysconfdir)\" \
// --- run.sh ---
rc=0

./tests/lint/eol-at-eof.sh $(git ls-files) || rc=1

./tests/lint/line_length.py $(git ls-files '*.[ch]') || rc=1
...
./tests/lint/astyle.sh $(git ls-files '*.[ch]') || rc=1

exit $rc
