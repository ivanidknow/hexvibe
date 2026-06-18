// Vulnerable: VUL-CVE-2023-27533
}

static CURLcode check_telnet_options(struct Curl_easy *data)
{
...
  if(data->state.aptr.user) {
    char buffer[256];
    msnprintf(buffer, sizeof(buffer), "USER,%s", data->conn->user);
    beg = curl_slist_append(tn->telnet_vars, buffer);
...
      olen = sep - option;
      arg = ++sep;
      switch(olen) {
      case 5:
