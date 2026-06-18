// Vulnerable: VUL-CVE-2015-9383
2015-10-31  Werner Lemberg  <wl@gnu.org>
// --- ttcmap.c ---
        if ( defOff != 0 )
        {
          FT_Byte*  defp      = table + defOff;
          FT_ULong  numRanges = TT_NEXT_ULONG( defp );
          FT_ULong  i;
          FT_ULong  lastBase  = 0;
...
          FT_ULong  numRanges = TT_NEXT_ULONG( defp );
          FT_ULong  i;
...
          /* numMappings * 4 > (FT_ULong)( valid->limit - ndp ) ? */
          if ( numMappings > ( (FT_ULong)( valid->limit - ndp ) ) / 4 )
            FT_INVALID_TOO_SHORT;
