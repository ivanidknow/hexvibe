// Vulnerable: VUL-CVE-2016-5009
}

  cmd_getval(g_ceph_context, cmdmap, "prefix", prefix);
  if (prefix == "get_command_descriptions") {
    bufferlist rdata;
...

  get_str_vec(prefix, fullcmd);
  module = fullcmd[0];
// --- cmd.cc ---
  cmd[0] = (char *)"asdfqwer";
  ASSERT_EQ(-EINVAL, rados_mon_command(cluster, (const char **)cmd, 1, "{}", 2, &buf, &buflen, &st, &stlen));
  rados_buffer_free(buf);
  rados_buffer_free(st);
