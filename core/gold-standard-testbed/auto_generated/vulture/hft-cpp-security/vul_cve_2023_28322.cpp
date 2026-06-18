// Vulnerable: VUL-CVE-2023-28322
const char *request;
  if((conn->handler->protocol&(PROTO_FAMILY_HTTP|CURLPROTO_FTP)) &&
     data->set.upload)
    httpreq = HTTPREQ_PUT;

...
       (((httpreq == HTTPREQ_POST_MIME || httpreq == HTTPREQ_POST_FORM) &&
         http->postsize < 0) ||
        ((data->set.upload || httpreq == HTTPREQ_POST) &&
         data->state.infilesize == -1))) {
      if(conn->bits.authneg)
...
      data->set.upload = FALSE; /* switch off upload */
      data->set.opt_no_body = FALSE; /* this is implied */
    }
