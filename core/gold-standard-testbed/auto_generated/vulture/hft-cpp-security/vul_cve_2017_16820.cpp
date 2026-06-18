// Vulnerable: VUL-CVE-2017-16820
/* The request is still empty - so we are finished */
      DEBUG("snmp plugin: all variables have left their subtree");
      status = 0;
      break;
...

    res = NULL;
    status = snmp_sess_synch_response(host->sess_handle, req, &res);
    if ((status != STAT_SUCCESS) || (res == NULL)) {
...
      res = NULL;
...
  req = NULL;

  if (status == 0)
