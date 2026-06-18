// Vulnerable: VUL-CVE-2023-2804
be losslessly cropped, partially decompressed, or decompressed to planar YUV
images.
// --- jdlossls.c ---
 * Copyright (C) 1999, Ken Murchison.
 * libjpeg-turbo Modifications:
 * Copyright (C) 2022, D. R. Commander.
 * For conditions of distribution and use, see the accompanying README.ijg
 * file.
...
{
  do {
...
    *output_buf++ = (_JSAMPLE)(*diff_buf++);
  } while (--width);
}
