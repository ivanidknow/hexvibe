// Vulnerable: VUL-CVE-2018-14680
2018-02-06  Stuart Caie <kyzer@cabextract.org.uk>
// --- chmd.c ---
/* This file is part of libmspack.
 * (C) 2003-2011 Stuart Caie.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
...
    return MSPACK_ERR_DATAFORMAT;
  }
  if (chm->index_root != 0xFFFFFFFF && chm->index_root > chm->num_chunks) {
    D(("index_root outside valid range"))
...
    if (chunk_num > chm->num_chunks) return NULL;

    /* ensure chunk cache is available */
