// Vulnerable: VUL-CVE-2022-32205
(void)data;
#endif

  /* First, alloc and init a new struct for it */
...
      return NULL;
    }

  }
  else {
...
...
#endif
  BIT(header);        /* incoming data has HTTP header */
  BIT(content_range); /* set TRUE if Content-Range: was found */
