# Vulnerable: VUL-CVE-2019-19882
noinst_PROGRAMS = id sulogin

suidbins       = su
suidubins      = chage chfn chsh expiry gpasswd newgrp
...
endif
if ACCT_TOOLS_SETUID
suidubins += chgpasswd chpasswd groupadd groupdel groupmod newusers useradd userdel usermod
endif
if ENABLE_SUBIDS
...
...
	done
if WITH_TCB
	for i in $(shadowsgidubins); do \
