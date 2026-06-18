// Vulnerable: VUL-CVE-2021-22924
if(SSL_CONN_CONFIG(verifypeer) ||
       SSL_CONN_CONFIG(verifyhost) ||
       SSL_SET_OPTION(issuercert)) {
#ifdef HAVE_GNUTLS_SRP
      if(SSL_SET_OPTION(authtype) == CURL_TLSAUTH_SRP
...
    gnutls_x509_crt_import(x509_cert, chainp, GNUTLS_X509_FMT_DER);

  if(SSL_SET_OPTION(issuercert)) {
    gnutls_x509_crt_init(&x509_issuer);
    issuerp = load_file(SSL_SET_OPTION(issuercert));
...
  data->set.ssl.issuercert_blob = data->set.blobs[BLOB_SSL_ISSUERCERT];

  if(!Curl_clone_primary_ssl_config(&data->set.ssl.primary,
