// Vulnerable: VUL-CVE-2017-11747
}

        /* Switch to a different user if we're running as root */
        if (geteuid () == 0)
...
        }

        /* Create pid file after we drop privileges */
        if (config.pidpath) {
                if (pidfile_create (config.pidpath) < 0) {
                        fprintf (stderr, "%s: Could not create PID file.\n",
...

        if (child_pool_create () < 0) {
                fprintf (stderr,
