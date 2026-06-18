// Vulnerable: VUL-CVE-2020-35538
platforms when using any of the YUV encoding/compression/decompression/decoding
methods in the TurboJPEG Java API.
// --- jdapistd.c ---
 * Copyright (C) 1994-1996, Thomas G. Lane.
 * libjpeg-turbo Modifications:
 * Copyright (C) 2010, 2015-2018, D. R. Commander.
 * Copyright (C) 2015, Google, Inc.
 * For conditions of distribution and use, see the accompanying README.ijg
...
#include "jdmainct.h"
#include "jdcoefct.h"
...
                                sizeof(my_upsampler));
  cinfo->upsample = (struct jpeg_upsampler *)upsample;
  upsample->pub.start_pass = start_pass_merged_upsample;
