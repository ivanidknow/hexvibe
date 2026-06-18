// Vulnerable: VUL-CVE-2021-46822
progressive JPEG format described in the report
["Two Issues with the JPEG Standard"](https://libjpeg-turbo.org/pmwiki/uploads/About/TwoIssueswiththeJPEGStandard.pdf).
// --- rdppm.c ---
 * Modified 2009 by Bill Allombert, Guido Vollbeding.
 * libjpeg-turbo Modifications:
 * Copyright (C) 2015-2017, 2020, D. R. Commander.
 * For conditions of distribution and use, see the accompanying README.ijg
 * file.
...
  JDIMENSION col;
  unsigned int maxval = source->maxval;
...
      source->pub.get_pixel_rows = get_word_rgb_row;
    } else if (maxval == MAXJSAMPLE && sizeof(JSAMPLE) == sizeof(U_CHAR) &&
#if RGB_RED == 0 && RGB_GREEN == 1 && RGB_BLUE == 2 && RGB_PIXELSIZE == 3
