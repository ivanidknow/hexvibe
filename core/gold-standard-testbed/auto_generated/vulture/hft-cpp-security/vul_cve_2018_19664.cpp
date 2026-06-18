// Vulnerable: VUL-CVE-2018-19664
occurred when attempting to load a BMP file with more than 1 billion pixels
using the 'tjLoadImage()' function.
// --- wrbmp.c ---
    else
      dest->pub.put_pixel_rows = put_pixel_rows;
  } else if (cinfo->out_color_space == JCS_RGB565 ||
             cinfo->out_color_space == JCS_CMYK) {
    dest->pub.put_pixel_rows = put_pixel_rows;
  } else {
