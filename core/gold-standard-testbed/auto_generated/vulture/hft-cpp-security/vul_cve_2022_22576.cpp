// Vulnerable: VUL-CVE-2022-22576
}

/* --- public functions --- */
// --- strcase.h ---
void Curl_strntolower(char *dest, const char *src, size_t n);

#endif /* HEADER_CURL_STRCASE_H */
// --- url.c ---
  Curl_safefree(conn->sasl_authzid);
  Curl_safefree(conn->options);
  Curl_dyn_free(&conn->trailer);
...
  char *sasl_authzid;     /* authorization identity string, allocated */
  unsigned char httpversion; /* the HTTP version*10 reported by the server */
  struct curltime now;     /* "current" time */
