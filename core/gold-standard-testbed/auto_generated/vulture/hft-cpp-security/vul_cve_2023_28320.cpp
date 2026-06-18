// Vulnerable: VUL-CVE-2023-28320
#endif

#if defined(CURLRES_SYNCH) && \
    defined(HAVE_ALARM) && defined(SIGALRM) && defined(HAVE_SIGSETJMP)
/* alarm-based timeouts can only be used with all the dependencies satisfied */
#define USE_ALARM_TIMEOUT
...
/* alarm-based timeouts can only be used with all the dependencies satisfied */
#define USE_ALARM_TIMEOUT
#endif

...
#endif /* HAVE_SIGACTION */

  /* switch back the alarm() to either zero or to what it was before minus
