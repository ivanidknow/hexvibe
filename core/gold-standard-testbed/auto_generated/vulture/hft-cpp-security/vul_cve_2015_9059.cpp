// Vulnerable: VUL-CVE-2015-9059
linenoise-1.0/linenoise.o : linenoise-1.0/linenoise.c linenoise-1.0/linenoise.h


picocom : picocom.o term.o
#	$(LD) $(LDFLAGS) -o $@ $+ $(LDLIBS)

...
picocom.o : picocom.c term.h
term.o : term.c term.h
// --- picocom.c ---
#include <getopt.h>
...
		run_cmd(tty_fd, xfr_cmd, fname, NULL);
		free(fname);
		break;
