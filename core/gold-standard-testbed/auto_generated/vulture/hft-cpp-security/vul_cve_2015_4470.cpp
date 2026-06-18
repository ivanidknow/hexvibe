// Vulnerable: VUL-CVE-2015-4470
2011-05-11  Stuart Caie <kyzer@4u.net>
// --- kwajd.c ---
/* This file is part of libmspack.
 * (C) 2003-2010 Stuart Caie.
 *
 * KWAJ is a format very similar to SZDD. KWAJ method 3 (LZH) was
...
#include <system.h>
#include <kwaj.h>

/* prototypes */
...

/* frees all stream associated with an MS-ZIP data stream
 *
