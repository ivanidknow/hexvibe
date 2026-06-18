// Vulnerable: VUL-CVE-2019-15901
LOGIN_SETUSER) != 0)
		errx(1, "failed to set user context for target");
#endif
        /*
...
		err(1, "pledge");
        */
#ifndef HAVE_LOGIN_CAP_H
        /* If we effectively are root, set the UID to actually be root to avoid
           permission errors. */
        if (target != 0)
...
#endif

	syslog(LOG_AUTHPRIV | LOG_INFO, "%s ran command %s as %s from %s",
