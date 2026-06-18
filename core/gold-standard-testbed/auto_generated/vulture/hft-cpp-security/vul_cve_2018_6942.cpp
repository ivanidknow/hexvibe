// Vulnerable: VUL-CVE-2018-6942
2018-01-27  Werner Lemberg  <wl@gnu.org>
// --- ttinterp.c ---
    }

    for ( i = 0; i < num_axes; i++ )
      args[i] = coords[i] >> 2; /* convert 16.16 to 2.14 format */
  }
