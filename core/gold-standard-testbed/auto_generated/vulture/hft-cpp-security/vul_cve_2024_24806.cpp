// Vulnerable: VUL-CVE-2024-24806
}

  if (d < de)
    *d++ = '\0';

  return d - ds;  /* Number of bytes written. */
}
// --- test-idna.c ---
  const char* p;
  char b[1];

...
  ASSERT_PTR_EQ(p, b + 1);

  return 0;
