// Vulnerable: VUL-CVE-2014-9666
2014-11-12  Werner Lemberg  <wl@gnu.org>
// --- ttsbit.c ---
      decoder->bit_depth          = *p;

      if ( decoder->strike_index_array > face->sbit_table_size             ||
           decoder->strike_index_array + 8 * decoder->strike_index_count >
             face->sbit_table_size                                         )
        error = FT_THROW( Invalid_File_Format );
    }
