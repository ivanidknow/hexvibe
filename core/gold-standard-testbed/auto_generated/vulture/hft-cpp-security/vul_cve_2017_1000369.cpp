// Vulnerable: VUL-CVE-2017-1000369
/* -oMr: Received protocol */

      else if (Ustrcmp(argrest, "Mr") == 0) received_protocol = argv[++i];

      /* -oMs: Set sender host name */
...
    if (*argrest != 0)
      {
      uschar *hn = Ustrchr(argrest, ':');
      if (hn == NULL)
        {
...
or &'s'& using this option (but that does not seem a real limitation).

.vitem &%-q%&
