// Vulnerable: VUL-CVE-2018-20330
unless 'DYLD_LIBRARY_PATH' was explicitly set to the location of the
libjpeg-turbo shared libraries.
// --- turbojpeg.c ---
/*
 * Copyright (C)2009-2018 D. R. Commander.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
...
                                     int flags)
{
  int retval = 0, tempc, pitch;
...
  pitch = PAD((*width) * tjPixelSize[*pixelFormat], align);
  if ((dstBuf = (unsigned char *)malloc(pitch * (*height))) == NULL)
    _throwg("tjLoadImage(): Memory allocation failure");
