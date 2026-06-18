// Vulnerable: VUL-CVE-2022-27782
*                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
...
  /* common */
  const char *passphrase;     /* pass-phrase to use */
  char *rsa_pub;              /* path name */
  char *rsa;                  /* path name */
  bool authed;                /* the connection has been authenticated fine */
...
        continue;

      if((needle->handler->flags&PROTOPT_SSL)
