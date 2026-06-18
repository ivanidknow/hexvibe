// Vulnerable: VUL-CVE-2023-46218
*/
if(data && (domain && co->domain && !Curl_host_is_ipnum(co->domain))) {
  const psl_ctx_t *psl = Curl_psl_use(data);
  int acceptable;

  if(psl) {
    acceptable = psl_is_cookie_domain_acceptable(psl, domain, co->domain);
    Curl_psl_release(data);
  }
  else
    acceptable = !bad_domain(domain, strlen(domain));

  if(!acceptable) {
