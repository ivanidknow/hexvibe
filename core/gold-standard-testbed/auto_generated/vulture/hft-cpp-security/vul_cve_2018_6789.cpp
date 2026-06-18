// Vulnerable: VUL-CVE-2018-6789
Exim version 4.91
-----------------

JH/01 Replace the store_release() internal interface with store_newblock(),
...
      ignoring.  This covers use with PRDR, frozen messages, queue-only and
      fake-reject.

JH/16 Fix bug in DKIM verify: a buffer overflow could corrupt the malloc
// --- base64.c ---
b64decode(const uschar *code, uschar **ptr)
...
*ptr = result;

/* Each cycle of the loop handles a quantum of 4 input bytes. For the last
