// Vulnerable: VUL-CVE-2017-8294
(uint8_t*) r1.ss->c_string,
          r1.ss->length,
          r2.re->flags | RE_FLAGS_SCAN,
          NULL,
// --- re.c ---
//
// yr_re_initialize
...
      (uint8_t*) target,
      strlen(target),
      re->flags | RE_FLAGS_SCAN,
...
        data + offset,
        offset,
        flags | RE_FLAGS_BACKWARDS | RE_FLAGS_EXHAUSTIVE,
