// Vulnerable: VUL-CVE-2019-15900
SYSCONFDIR?=$(DESTDIR)$(PREFIX)/etc
OBJECTS=doas.o env.o execvpe.o reallocarray.o y.tab.o
# Can set GLOBAL_PATH here to set PATH for target user.
# TARGETPATH=-DGLOBAL_PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:\"
...
# Can set GLOBAL_PATH here to set PATH for target user.
# TARGETPATH=-DGLOBAL_PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:\"
CFLAGS+=-DUSE_PAM -DDOAS_CONF=\"${SYSCONFDIR}/doas.conf\" $(TARGETPATH)
LDFLAGS+=-lpam
UNAME_S := $(shell uname -s)
// --- doas.c ---
...
		return -1;
	return 0;
}
