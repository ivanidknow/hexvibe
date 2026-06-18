// Vulnerable: VUL-CVE-2021-22890
Curl_ssl_sessionid_lock(data);
    if(!Curl_ssl_getsessionid(data, conn, &session, NULL, sockindex)) {
      br_ssl_engine_set_session_parameters(&backend->ctx.eng, session);
      infof(data, "BearSSL: re-using session ID\n");
...
    Curl_ssl_sessionid_lock(data);
    incache = !(Curl_ssl_getsessionid(data, conn,
                                      &oldsession, NULL, sockindex));
    if(incache)
...
    if(incache)
...
        data, conn, our_ssl_sessionid, 0 /* unknown size */, sockindex);
      if(result) {
        Curl_ssl_sessionid_unlock(data);
