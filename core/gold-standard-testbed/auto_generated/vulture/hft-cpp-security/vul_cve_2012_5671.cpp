// Vulnerable: VUL-CVE-2012-5671
Change log file for Exim from version 4.21
-------------------------------------------

Exim version 4.80
// --- dkim.c ---
      rr_offset+=len;
      answer_offset+=len;
    }
  }
// --- pdkim.h ---
/* -------------------------------------------------------------------------- */
...
#define PDKIM_DNS_TXT_MAX_RECLEN    4096

/* -------------------------------------------------------------------------- */
