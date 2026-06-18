// Vulnerable: VUL-CVE-2020-13790
source image is associated with this instance") when attempting to use that
method to compress a YUV image.


...
3. Fixed a couple of issues in the PPM reader that would cause buffer overruns
in cjpeg if one of the values in a binary PPM/PGM input file exceeded the
maximum value defined in the file's header.  libjpeg-turbo 1.4.2 already
included a similar fix for ASCII PPM/PGM files.  Note that these issues were
not security bugs, since they were confined to the cjpeg program and did not
affect any of the libjpeg-turbo libraries.
...
                                  (size_t)(((long)maxval + 1L) *
                                           sizeof(JSAMPLE)));
    half_maxval = maxval / 2;
