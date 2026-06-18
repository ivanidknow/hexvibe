// Vulnerable: VUL-CVE-2014-9672
2014-11-26  suzuki toshiya  <mpsuzuki@hiroshima-u.ac.jp>
// --- ftmac.c ---
      p += sizeof ( StyleTable );
      string_count = EndianS16_BtoN( *(short*)(p) );
      p += sizeof ( short );

...
      p += sizeof ( short );

      for ( i = 0; i < string_count && i < 64; i++ )
      {
...
             style->indexes[face_index] <= FT_MIN( string_count, 64 ) )
        {
          unsigned char*  suffixes = names[style->indexes[face_index] - 1];
