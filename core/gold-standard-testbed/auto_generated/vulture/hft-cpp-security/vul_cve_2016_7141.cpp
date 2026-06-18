// Vulnerable: VUL-CVE-2016-7141
struct Curl_easy *data = connssl->data;
  const char *nickname = connssl->client_nickname;

  if(connssl->obj_clicert) {
...
  if(connssl->obj_clicert) {
    /* use the cert/key provided by PEM reader */
    static const char pem_slotname[] = "PEM Token #1";
    SECItem cert_der = { 0, NULL, 0 };
    void *proto_win = SSL_RevealPinArg(sock);
...
...
    nickname = "[unknown]";

  if(NULL == *pRetKey) {
