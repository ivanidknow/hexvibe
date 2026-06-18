# Vulnerable: VUL-CVE-2020-8284
.\" *                             \___|\___/|_| \_\_____|
.\" *
.\" * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
.\" *
.\" * This software is licensed as described in the file COPYING, which
...

This option thus allows libcurl to work around broken server installations
that due to NATs, firewalls or incompetence report the wrong IP address back.

This option has no effect if PORT, EPRT or EPSV is used instead of PASV.
...
  curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt(hnd, CURLOPT_PROTOCOLS, (long)CURLPROTO_FILE |
