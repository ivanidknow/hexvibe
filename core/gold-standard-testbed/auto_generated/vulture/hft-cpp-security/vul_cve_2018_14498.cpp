// Vulnerable: VUL-CVE-2018-14498
7. The new CMake-based build system will now disable the MIPS DSPr2 SIMD
extensions if it detects that the compiler does not support DSPr2 instructions.
// --- cderror.h ---
 *
 * Copyright (C) 1994-1997, Thomas G. Lane.
 * Modified 2009 by Guido Vollbeding.
 * This file is part of the Independent JPEG Group's software.
 * For conditions of distribution and use, see the accompanying README.ijg
...
JMESSAGE(JERR_BMP_EMPTY, "Empty BMP image")
JMESSAGE(JERR_BMP_NOT, "Not a BMP file - does not start with BM")
...
      ERREXIT(cinfo, JERR_PPM_TOOLARGE);
    *ptr++ = rescale[temp];
  }
