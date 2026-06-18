// Vulnerable: VUL-CVE-2014-9662
2014-01-26  Werner Lemberg  <wl@gnu.org>
// --- cf2ft.c ---
    FT_ASSERT( unitsPerEm > 0 );

    FT_ASSERT( transform->a > 0 && transform->d > 0 );
    FT_ASSERT( transform->b == 0 && transform->c == 0 );
    FT_ASSERT( transform->tx == 0 && transform->ty == 0 );
...
      font->unitsPerEm = (CF2_Int)cf2_getUnitsPerEm( decoder );

      error2 = cf2_checkTransform( &transform, font->unitsPerEm );
...

    return cf2_intToFixed(
             decoder->builder.face->root.size->metrics.y_ppem );
