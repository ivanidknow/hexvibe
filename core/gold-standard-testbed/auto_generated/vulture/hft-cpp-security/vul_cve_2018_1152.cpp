// Vulnerable: VUL-CVE-2018-1152
PPM readers/writers threw an error that was specific to the readers/writers
(as opposed to a general libjpeg API error.)
// --- rdbmp.c ---
 * libjpeg-turbo Modifications:
 * Modified 2011 by Siarhei Siamashka.
 * Copyright (C) 2015, 2017, D. R. Commander.
 * For conditions of distribution and use, see the accompanying README.ijg
 * file.
...
  }

  /* Allocate one-row buffer for returned data */
  source->pub.buffer = (*cinfo->mem->alloc_sarray)
