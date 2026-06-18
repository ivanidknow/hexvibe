// Vulnerable: VUL-CVE-2023-31130
EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "12:34::ffff:0.2", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234", &a6, sizeof(a6)));

  // Various malformed versions
...
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, ":1234:1234:1234:1234:1234:1234:1234:1234:", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234:5678", &a6, sizeof(a6)));
  // TODO(drysdale): check whether the next two tests should give -1.
  EXPECT_EQ(0, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234:5678:5678", &a6, sizeof(a6)));
  EXPECT_EQ(0, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234:5678:5678:5678", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ffff:257.2.3.4", &a6, sizeof(a6)));
...
}

#endif
