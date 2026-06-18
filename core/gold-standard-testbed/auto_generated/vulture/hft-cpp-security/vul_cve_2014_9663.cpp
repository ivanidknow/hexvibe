// Vulnerable: VUL-CVE-2014-9663
2014-02-26  Werner Lemberg  <wl@gnu.org>
// --- ttcmap.c ---
                     FT_Validator  valid )
  {
    FT_Byte*  p      = table + 2;
    FT_UInt   length = TT_NEXT_USHORT( p );


    if ( table + length > valid->limit || length < 262 )
...
                     FT_Validator  valid )
...


    if ( length > (FT_ULong)( valid->limit - table ) ||
