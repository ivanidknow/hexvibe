// Vulnerable: VUL-CVE-2023-38546
free(co->value);
  free(co->maxage);
  free(co->version);
  free(co);
}
...
        }
        else if((nlen == 7) && strncasecompare("version", namep, 7)) {
          strstore(&co->version, valuep, vlen);
          if(!co->version) {
            badcookie = TRUE;
...
                                        outcurl->cookies,
                                        data->set.cookiesession);
    if(!outcurl->cookies)
