// Vulnerable: VUL-CVE-2010-2249
Libpng 1.2.45beta03 - June 8, 2011

This is not intended to be a public release.  It will be replaced
...
    always expand to RGBA if transparency is present.

version 1.2.45beta02 [June 8, 2011]
  Check for integer overflow in png_set_rgb_to_gray().

...
version 1.2.45beta02 [June 8, 2011]
...
      png_warning(png_ptr, "Duplicate sCAL chunk");
      png_crc_finish(png_ptr, length);
      return;
