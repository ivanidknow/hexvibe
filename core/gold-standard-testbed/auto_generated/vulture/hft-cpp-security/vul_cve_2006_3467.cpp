// Vulnerable: VUL-CVE-2006-3467
2002-04-15  David Turner  <david@freetype.org>
// --- pcfread.c ---
    }

    error = pcf_get_metric( stream, format, &(accel->minbounds) );
    if ( error )
      goto Bail;

    error = pcf_get_metric( stream, format, &(accel->maxbounds) );
    if ( error )
      goto Bail;
...
      error = pcf_get_metric( stream, format, &(accel->ink_maxbounds) );
      if ( error )
        goto Bail;
