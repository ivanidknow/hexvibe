// Vulnerable: VUL-CVE-2016-9586
}

static int string_check(char *buf, const char *buf2)
{
  if(strcmp(buf, buf2)) {
...
  if(strcmp(buf, buf2)) {
    /* they shouldn't differ */
    printf("sprintf failed:\nwe '%s'\nsystem: '%s'\n",
           buf, buf2);
    return 1;
...

        for(fptr=work; *fptr; fptr++)
          OUTCHAR(*fptr);
