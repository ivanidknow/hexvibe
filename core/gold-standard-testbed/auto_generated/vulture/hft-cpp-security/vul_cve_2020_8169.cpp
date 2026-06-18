// Vulnerable: VUL-CVE-2020-8169
/* for updated strings, we update them in the URL */
  if(user_changed) {
    uc = curl_url_set(data->state.uh, CURLUPART_USER, *userp, 0);
    if(uc)
      return Curl_uc_to_curlcode(uc);
...
  }
  if(passwd_changed) {
    uc = curl_url_set(data->state.uh, CURLUPART_PASSWORD, *passwdp, 0);
    if(uc)
      return Curl_uc_to_curlcode(uc);
