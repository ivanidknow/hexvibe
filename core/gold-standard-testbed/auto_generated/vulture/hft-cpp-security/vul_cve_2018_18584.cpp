// Vulnerable: VUL-CVE-2018-18584
2018-10-17  Stuart Caie <kyzer@cabextract.org.uk>
// --- cab.h ---
/* This file is part of libmspack.
 * (C) 2003-2004 Stuart Caie.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
...
#define CAB_INPUTMAX (CAB_BLOCKMAX+6144)

/* There are no more than 65535 data blocks per folder, so a folder cannot
 * be more than 32768*65535 bytes in length. As files cannot span more than
...
  unsigned char *i_ptr, *i_end;      /* input data consumed, end             */
  unsigned char input[CAB_INPUTMAX]; /* one input block of data              */
};
