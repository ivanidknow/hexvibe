// Vulnerable: VUL-CVE-2018-1000007
conn->bits.netrc ||
     !data->state.first_host ||
     data->set.http_disable_hostname_check_before_authentication ||
     strcasecompare(data->state.first_host, conn->host.name)) {
    result = output_auth_headers(conn, authhost, request, path, FALSE);
...
                  checkprefix("Transfer-Encoding:", headers->data))
            /* HTTP/2 doesn't support chunked requests */
            ;
          else {
// --- setopt.c ---
...
    data->set.http_disable_hostname_check_before_authentication =
      (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
