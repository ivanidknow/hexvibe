// Vulnerable: VUL-CVE-2019-3804
}

static char *
base64_decode_string (const char *enc)
{
...
base64_decode_string (const char *enc)
{
  if (enc == NULL)
    return NULL;
...
...
  g_hash_table_insert (headers, g_strdup ("Cookie"), g_strdup ("CockpitAuth=v=2;k=blah"));
  if (cockpit_auth_check_cookie (test->auth, "/cockpit", headers))
      g_assert_not_reached ();
