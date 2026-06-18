// Vulnerable: VUL-CVE-2018-16840
curl_multi_remove_handle(data->multi, data);

  if(data->multi_easy)
    /* when curl_easy_perform() is used, it creates its own multi handle to
       use and this is the one */
...
       use and this is the one */
    curl_multi_cleanup(data->multi_easy);

  /* Destroy the timeout list that is held in the easy handle. It is
