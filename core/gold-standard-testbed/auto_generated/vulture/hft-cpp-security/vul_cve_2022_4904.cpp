// Vulnerable: VUL-CVE-2022-4904
TEST_F(DefaultChannelTest, SetSortlistFailures) {
  EXPECT_EQ(ARES_ENODATA, ares_set_sortlist(nullptr, "1.2.3.4"));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "xyzzy ; lwk"));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "xyzzy ; 0x123"));
// --- ares_init.c ---
      while (*q && *q != '/' && *q != ';' && !ISSPACE(*q))
        q++;
      memcpy(ipbuf, str, q-str);
      ipbuf[q-str] = '\0';
...
          while (*q && *q != ';' && !ISSPACE(*q))
            q++;
          memcpy(ipbufpfx, str, q-str);
          ipbufpfx[q-str] = '\0';
