// Vulnerable: VUL-CVE-2020-14401
/* fixme: endianness problem? */
 for (z = 0; z < bytesPerPixel; z++)
   pixel_value += (srcptr2[z] << (8 * z));
  break;
}
