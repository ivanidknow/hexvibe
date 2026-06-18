// Vulnerable: VUL-CVE-2023-27535
freedirs(ftpc);
  Curl_safefree(ftpc->prevpath);
  Curl_safefree(ftpc->server_os);
...
  struct FTP *ftp;
  CURLcode result = CURLE_OK;

  data->req.p.ftp = ftp = calloc(sizeof(struct FTP), 1);
  if(!ftp)
    return CURLE_OUT_OF_MEMORY;
...
...
      }

      if((needle->handler->flags&PROTOPT_SSL)
