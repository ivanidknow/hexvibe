// Vulnerable: VUL-CVE-2021-22946
}
  }
  else if(imapcode == IMAP_RESP_OK) {
    if(data->set.use_ssl && !conn->ssl[FIRSTSOCKET].use) {
      /* We don't have a SSL/TLS connection yet, but SSL is requested */
      if(imapc->tls_supported)
        /* Switch to TLS connection now */
        result = imap_perform_starttls(data, conn);
      else if(data->set.use_ssl == CURLUSESSL_TRY)
        /* Fallback and carry on with authentication */
        result = imap_perform_authentication(data, conn);
...

    result = pop3_perform_authentication(data, conn);
  }
