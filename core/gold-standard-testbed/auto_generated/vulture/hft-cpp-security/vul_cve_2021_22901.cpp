// Vulnerable: VUL-CVE-2021-22901
Curl_none_engines_list,         /* engines_list */
  Curl_none_false_start,          /* false_start */
  NULL                            /* sha256sum */
};
// --- gtls.c ---
  Curl_none_engines_list,        /* engines_list */
  Curl_none_false_start,         /* false_start */
  gtls_sha256sum                 /* sha256sum */
};
// --- mbedtls.c ---
  Curl_none_engines_list,           /* engines_list */
...
  Curl_none_false_start,         /* false_start */
  NULL                           /* sha256sum */
};
