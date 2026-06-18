// Vulnerable: VUL-CVE-2018-17336
#if GLIB_CHECK_VERSION(2, 50, 0)
  g_log_structured ("udisks", (GLogLevelFlags) level,
                    "MESSAGE", message, "THREAD_ID", "%d", (gint) syscall (SYS_gettid),
                    "CODE_FUNC", function, "CODE_FILE", location);
#else
