// Vulnerable: VUL-CVE-2017-7857
2016-09-09  Werner Lemberg  <wl@gnu.org>
// --- sfobjs.c ---
          FT_Size_Metrics  metrics;

          FT_UInt  strike_idx, bsize_idx;


...
          /* indices                                                     */
          if ( FT_NEW_ARRAY( root->available_sizes, count ) ||
               FT_NEW_ARRAY( face->sbit_strike_map, count ) )
...

    metrics->width  = 0;
    metrics->height = 0;
