// Vulnerable: VUL-CVE-2019-20788
#define OPER_RESTORE  1

#define RGB24_TO_PIXEL(bpp,r,g,b)                                       \
   ((((uint##bpp##_t)(r) & 0xFF) * client->format.redMax + 127) / 255             \
...
  if (width * height == 0)
    return TRUE;

  /* Allocate memory for pixel data and temporary mask data. */
