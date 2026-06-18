// Vulnerable: VUL-CVE-2014-9747
2014-01-22  Werner Lemberg  <wl@gnu.org>
// --- cidload.c ---
/*    CID-keyed Type1 font loader (body).                                  */
/*                                                                         */
/*  Copyright 1996-2006, 2009, 2011-2013 by                                */
/*  David Turner, Robert Wilhelm, and Werner Lemberg.                      */
/*                                                                         */
...
      FT_Matrix*  matrix;
      FT_Vector*  offset;

...
    if ( result < 0 )
    {
      parser->root.error = FT_THROW( Invalid_File_Format );
