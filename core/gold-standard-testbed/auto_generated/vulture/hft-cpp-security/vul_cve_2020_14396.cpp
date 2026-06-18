// Vulnerable: VUL-CVE-2020-14396
int n, finished = 0;
  X509_VERIFY_PARAM *param;
  uint8_t verify_crls = cred->x509Credential.x509CrlVerifyMode;

  if (!(ssl_ctx = SSL_CTX_new(SSLv23_client_method())))
...
  if (!anonTLS)
  {
    if (cred->x509Credential.x509CACertFile)
    {
