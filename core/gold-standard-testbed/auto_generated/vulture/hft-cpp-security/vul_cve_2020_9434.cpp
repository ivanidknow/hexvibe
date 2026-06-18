// Vulnerable: VUL-CVE-2020-9434
}

#if OPENSSL_VERSION_NUMBER > 0x10002000L
/***
...
{
  X509 * cert = CHECK_OBJECT(1, X509, "openssl.x509");
  if (lua_isstring(L, 2))
  {
    const char *hostname = lua_tostring(L, 2);
    lua_pushboolean(L, X509_check_host(cert, hostname, strlen(hostname), 0, NULL));
...

  return 1;
}
