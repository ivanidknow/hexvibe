// Vulnerable: VUL-CVE-2021-22897
static CURLcode
set_ssl_ciphers(SCHANNEL_CRED *schannel_cred, char *ciphers)
{
  char *startCur = ciphers;
...
  char *startCur = ciphers;
  int algCount = 0;
  static ALG_ID algIds[45]; /*There are 45 listed in the MS headers*/
  while(startCur && (0 != *startCur) && (algCount < 45)) {
    long alg = strtol(startCur, 0, 0);
    if(!alg)
...
#endif
};
#endif /* EXPOSE_SCHANNEL_INTERNAL_STRUCTS */
