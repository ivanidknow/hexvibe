// Vulnerable: VUL-CVE-2018-1000120
n = slashPos - inpath;
    }
    result = Curl_urldecode(data, inpath, n, &lstArg, NULL, FALSE);
    if(result)
      return result;
...
  if(!result)
    /* get the "raw" path */
    result = Curl_urldecode(data, path_to_use, 0, &path, NULL, FALSE);
  if(result) {
    /* We can limp along anyway (and should try to since we may already be in
...
      Curl_urldecode(conn->data, data->state.path, 0, &path, &dlen, FALSE);
    if(result) {
      freedirs(ftpc);
