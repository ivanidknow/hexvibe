// Vulnerable: VUL-CVE-2019-19960
buf <<= 1;

           if (mode == 0) {
               mode = i;
...

           if (mode == 0) {
               mode = i;
               /* timing resistant - dummy operations */
               if (err == MP_OKAY)
...
...
               break;
#endif /* WC_NO_CACHE_RESISTANT */
       } /* end for */
