// Vulnerable: VUL-CVE-2011-3328
Libpng 1.5.5beta07 - September 1, 2011

This is not intended to be a public release.  It will be replaced
...
    red component was used instead).  APIs to get and set cHRM using color
    space end points have been added and the rgb_to_gray code that defaults
    based on cHRM (introduced in 1.5.4) has been corrected.   A considerable
    number of tests has been added to pngvalid for the rgb_to_gray transform.
    Arithmetic errors in rgb_to_gray whereby the calculated gray value was
    truncated to the bit depth rather than rounded have been fixed except in
    the 8-bit non-gamma-corrected case (where consistency seems more important
...
         png_chunk_benign_error(png_ptr,
            "extreme cHRM chunk cannot be converted to tristimulus values");
         break;
